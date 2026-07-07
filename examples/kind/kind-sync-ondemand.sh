#!/bin/bash
# kind-sync-ondemand.sh
#
# Regression test for https://github.com/project-zot/zot/issues/4184
#
# Docker manifest-list images like registry.k8s.io/pause:3.10.1 used to trigger
# an endless resync loop because zot's OCI digest prediction did not match
# regclient's post-conversion digest, causing CanSkipImage to always return false.
#
# This test:
#   1. Builds a minimal Docker image that packages the locally compiled zot binary.
#   2. Runs the container as a registry that mirrors registry.k8s.io on-demand.
#   3. Creates a kind cluster with containerd configured to use zot as a mirror
#      for registry.k8s.io.
#   4. Pulls registry.k8s.io/pause:3.10.1 via the kind node's crictl (first sync).
#   5. Evicts the image from the kind node's containerd store.
#   6. Pulls the same image again (second sync request to zot).
#   7. Asserts:
#      - The image appears in zot's catalog after the first sync.
#      - "skipping image because it's already synced" appears in zot logs.
#      - "remote image digest changed, syncing again" does NOT appear (no loop).

set -o errexit
set -o pipefail

ROOT_DIR=$(git rev-parse --show-toplevel)
cd "${ROOT_DIR}"

OS=$(go env GOOS)
ARCH=$(go env GOARCH)
ZOT_BINARY="${ROOT_DIR}/bin/zot-${OS}-${ARCH}"

# Prefer the project-local kind binary installed by check-blackbox-prerequisites.
if [ -x "${ROOT_DIR}/hack/tools/bin/kind" ]; then
    KIND="${ROOT_DIR}/hack/tools/bin/kind"
elif command -v kind &>/dev/null; then
    KIND="kind"
else
    echo "Error: kind not found. Run 'make check-blackbox-prerequisites' first." >&2
    exit 1
fi

CLUSTER_NAME="zot-sync-ondemand"
ZOT_CONTAINER_NAME="zot-sync-ondemand"
ZOT_PORT="5000"
KIND_NODE_IMAGE="kindest/node:v1.28.7"

# The image that triggered the issue: a Docker manifest-list with ~20 platforms.
PAUSE_IMAGE="registry.k8s.io/pause:3.10.1"

COMMIT_HASH=$(git describe --always --tags --long)
ZOT_IMAGE="zot-sync-ondemand:${COMMIT_HASH}"

ZOT_STORAGE=$(mktemp -d /tmp/zot-sync-storage-XXXXX)
ZOT_CONFIG=$(mktemp /tmp/zot-sync-config-XXXXX.json)

log_info()  { echo "[INFO]  $*"; }
log_error() { echo "[ERROR] $*" >&2; }

cleanup() {
    log_info "Cleaning up..."
    "${KIND}" delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
    docker rm -f "${ZOT_CONTAINER_NAME}" 2>/dev/null || true
    docker rmi -f "${ZOT_IMAGE}" 2>/dev/null || true
    rm -f "${ZOT_CONFIG}" 2>/dev/null || true
    rm -rf "${ZOT_STORAGE}" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
for cmd in docker kubectl curl jq git; do
    if ! command -v "$cmd" &>/dev/null; then
        log_error "$cmd is required but not found"
        exit 1
    fi
done

if [ ! -x "${ZOT_BINARY}" ]; then
    log_error "zot binary not found at ${ZOT_BINARY}. Run 'make binary' first."
    exit 1
fi

# ---------------------------------------------------------------------------
# Build a minimal zot Docker image from the locally compiled binary.
# Using gcr.io/distroless/base-debian12 (includes CA certificates) avoids a
# full recompile while still giving the image the TLS roots it needs to reach
# registry.k8s.io.
# ---------------------------------------------------------------------------
log_info "Building zot Docker image (${ZOT_IMAGE}) from local binary..."
BUILD_CTX=$(mktemp -d)
cp "${ZOT_BINARY}" "${BUILD_CTX}/zot"
docker build \
    --platform "linux/${ARCH}" \
    -t "${ZOT_IMAGE}" \
    -f - "${BUILD_CTX}" <<'DOCKER'
FROM gcr.io/distroless/base-debian12:latest
COPY zot /usr/bin/zot
ENTRYPOINT ["/usr/bin/zot"]
EXPOSE 5000
DOCKER
rm -rf "${BUILD_CTX}"
log_info "Image built: ${ZOT_IMAGE}"

# ---------------------------------------------------------------------------
# Write the zot sync configuration.
# ---------------------------------------------------------------------------
mkdir -p "${ZOT_STORAGE}"
cat > "${ZOT_CONFIG}" <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "/var/lib/registry"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${ZOT_PORT}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": ["https://registry.k8s.io"],
                    "onDemand": true,
                    "tlsVerify": true,
                    "content": [{"prefix": "**"}]
                }
            ]
        }
    }
}
EOF

# ---------------------------------------------------------------------------
# Start the zot container (not yet on the kind network).
# ---------------------------------------------------------------------------
log_info "Starting zot container (${ZOT_CONTAINER_NAME})..."
docker rm -f "${ZOT_CONTAINER_NAME}" 2>/dev/null || true
docker run -d \
    --name "${ZOT_CONTAINER_NAME}" \
    -p "127.0.0.1:${ZOT_PORT}:${ZOT_PORT}" \
    -v "${ZOT_CONFIG}:/etc/zot/config.json:ro" \
    -v "${ZOT_STORAGE}:/var/lib/registry" \
    "${ZOT_IMAGE}" serve /etc/zot/config.json

log_info "Waiting for zot to be ready..."
for i in $(seq 1 30); do
    if curl -sf "http://localhost:${ZOT_PORT}/v2/" >/dev/null 2>&1; then
        log_info "Zot is ready"
        break
    fi
    [ "${i}" -lt 30 ] || { log_error "Zot did not start in time"; docker logs "${ZOT_CONTAINER_NAME}"; exit 1; }
    sleep 1
done

# ---------------------------------------------------------------------------
# Create the kind cluster with registry.k8s.io mirrored to the zot container.
# The mirror references the container by name; DNS resolves after we join the
# kind network below.
# ---------------------------------------------------------------------------
log_info "Creating kind cluster '${CLUSTER_NAME}'..."
"${KIND}" get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}" && \
    "${KIND}" delete cluster --name "${CLUSTER_NAME}"

cat <<EOF | "${KIND}" create cluster --name "${CLUSTER_NAME}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: ${KIND_NODE_IMAGE}
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."registry.k8s.io"]
    endpoint = ["http://${ZOT_CONTAINER_NAME}:${ZOT_PORT}"]
EOF

# Connect the zot container to the kind Docker network so kind nodes can reach
# it by container name.
if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${ZOT_CONTAINER_NAME}")" = 'null' ]; then
    docker network connect kind "${ZOT_CONTAINER_NAME}"
fi

log_info "Cluster ready"
kubectl --context "kind-${CLUSTER_NAME}" get nodes

CONTROL_PLANE="${CLUSTER_NAME}-control-plane"

# ---------------------------------------------------------------------------
# First pull: deploy a pod whose container image is pause:3.10.1.
# This causes the kind node's containerd to pull through the zot mirror.
# ---------------------------------------------------------------------------
log_info "First pull: creating pod with image ${PAUSE_IMAGE}..."
kubectl --context "kind-${CLUSTER_NAME}" run pause-first \
    --image="${PAUSE_IMAGE}" \
    --restart=Never \
    --image-pull-policy=Always

log_info "Waiting for pause-first pod..."
for i in $(seq 1 60); do
    PHASE=$(kubectl --context "kind-${CLUSTER_NAME}" get pod pause-first \
        -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
    case "${PHASE}" in
        Running|Succeeded) break ;;
        Failed)
            log_error "pause-first pod failed"
            kubectl --context "kind-${CLUSTER_NAME}" describe pod pause-first
            docker logs "${ZOT_CONTAINER_NAME}"
            exit 1
            ;;
    esac
    [ "${i}" -lt 60 ] || { log_error "pause-first pod did not start within 120s"; exit 1; }
    sleep 2
done
log_info "pause-first pod phase: ${PHASE}"

# Verify the image is now in zot's catalog.
log_info "Verifying pause:3.10.1 exists in zot catalog..."
TAGS=$(curl -sf "http://localhost:${ZOT_PORT}/v2/pause/tags/list" 2>/dev/null || echo "{}")
if ! echo "${TAGS}" | jq -e '.tags | index("3.10.1")' >/dev/null 2>&1; then
    log_error "pause:3.10.1 was not found in zot after first sync"
    echo "Tags response: ${TAGS}"
    docker logs "${ZOT_CONTAINER_NAME}"
    exit 1
fi
log_info "pause:3.10.1 confirmed in zot catalog"

# ---------------------------------------------------------------------------
# Evict the image from the kind node's containerd image store so the next pod
# creation triggers a fresh pull request to zot (the skip-check path).
# ---------------------------------------------------------------------------
log_info "Removing pause-first pod and evicting image from kind node..."
kubectl --context "kind-${CLUSTER_NAME}" delete pod pause-first --ignore-not-found=true
# Wait for pod to be fully gone before evicting image
kubectl --context "kind-${CLUSTER_NAME}" wait --for=delete pod/pause-first --timeout=30s 2>/dev/null || true
docker exec "${CONTROL_PLANE}" crictl rmi "${PAUSE_IMAGE}" 2>/dev/null || \
    log_info "Image was not cached or already removed (continuing)"

# ---------------------------------------------------------------------------
# Second pull: re-create the pod.  The kind node pulls from zot again;  zot
# must recognise the image as already synced and skip re-downloading it from
# registry.k8s.io.
# ---------------------------------------------------------------------------
log_info "Second pull: creating pod with image ${PAUSE_IMAGE} (should be skipped by zot)..."
kubectl --context "kind-${CLUSTER_NAME}" run pause-second \
    --image="${PAUSE_IMAGE}" \
    --restart=Never \
    --image-pull-policy=Always

log_info "Waiting for pause-second pod..."
for i in $(seq 1 60); do
    PHASE=$(kubectl --context "kind-${CLUSTER_NAME}" get pod pause-second \
        -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
    case "${PHASE}" in
        Running|Succeeded) break ;;
        Failed)
            log_error "pause-second pod failed"
            kubectl --context "kind-${CLUSTER_NAME}" describe pod pause-second
            docker logs "${ZOT_CONTAINER_NAME}"
            exit 1
            ;;
    esac
    [ "${i}" -lt 60 ] || { log_error "pause-second pod did not start within 120s"; exit 1; }
    sleep 2
done
log_info "pause-second pod phase: ${PHASE}"

# Give the zot container a moment to flush log buffers.
sleep 2

# ---------------------------------------------------------------------------
# Assert correct sync behaviour from zot logs.
# ---------------------------------------------------------------------------
ZOT_LOGS=$(docker logs "${ZOT_CONTAINER_NAME}" 2>&1)

log_info "=== Asserting zot sync behaviour ==="

# 1. The second pull must have been skipped (already synced).
if ! echo "${ZOT_LOGS}" | grep "skipping image because it's already synced" | grep -q "pause"; then
    log_error "FAIL: pause:3.10.1 was not skipped on the second pull"
    echo "=== Zot log excerpt (pause lines) ==="
    echo "${ZOT_LOGS}" | grep -i pause | tail -40
    exit 1
fi

# 2. The digest-change resync loop must NOT have occurred.
if echo "${ZOT_LOGS}" | grep "remote image digest changed, syncing again" | grep -q "pause"; then
    log_error "FAIL: pause:3.10.1 triggered a resync loop (issue #4184 regression)"
    echo "=== Zot log excerpt (resync lines) ==="
    echo "${ZOT_LOGS}" | grep "remote image digest changed" | tail -20
    exit 1
fi

log_info "SUCCESS: ${PAUSE_IMAGE} synced without resync loop (issue #4184 verified fixed)"
