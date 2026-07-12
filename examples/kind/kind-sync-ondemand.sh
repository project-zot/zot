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
#   4. Evicts any pre-cached pause image, then pulls registry.k8s.io/pause:3.10.1 via zot mirror.
#   5. Evicts the image from the kind node with crictl rmi.
#   6. Pulls the same image again (second sync request to zot).
#   7. Asserts:
#      - The image appears in zot's catalog after the first sync.
#      - "skipping image because it's already synced" appears in zot logs on the
#        second pull only (not after the first).
#      - "remote image digest changed, syncing again" does NOT appear (no loop).
#
# Prerequisites:
#   make check-blackbox-prerequisites binary
#
# Usage:
#   make run-kind-sync-ondemand
#   ./examples/kind/kind-sync-ondemand.sh

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

ZOT_LISTEN_PORT="5000"
KIND_NODE_IMAGE="kindest/node:v1.28.7"
# pause:3.10.1 is a ~20-platform manifest list; first on-demand sync can take 1-3 minutes.
POD_WAIT_TIMEOUT="180s"

# The image that triggered the issue: a Docker manifest-list with ~20 platforms.
PAUSE_IMAGE="registry.k8s.io/pause:3.10.1"

COMMIT_HASH=$(git describe --always --tags --long)
RUN_SUFFIX="$(git rev-parse --short HEAD)-$$"
CLUSTER_NAME="zot-sync-ondemand-${RUN_SUFFIX}"
ZOT_CONTAINER_NAME="zot-sync-ondemand-${RUN_SUFFIX}"
CONTROL_PLANE="${CLUSTER_NAME}-control-plane"
ZOT_IMAGE="zot-sync-ondemand:${COMMIT_HASH}"
# Pinned digest for reproducible CI/nightly runs (index digest; docker --platform selects arch).
DISTROLESS_BASE_IMAGE="gcr.io/distroless/base-debian12@sha256:9c05cfd65f41c93a909ea67eb05b920a3b838780ea55df5421d48295d98ff957"

ZOT_STORAGE=$(mktemp -d /tmp/zot-sync-storage-XXXXX)
KUBECONFIG_FILE=$(mktemp /tmp/kind-sync-kubeconfig-XXXXX)
export KUBECONFIG="${KUBECONFIG_FILE}"

log_info()  { echo "[INFO]  $*"; }
log_warn()  { echo "[WARN]  $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }

KUBECTL_CTX="kind-${CLUSTER_NAME}"

wait_for_cluster_ready() {
    log_info "Waiting for kind node(s) to be Ready..."
    kubectl --context "${KUBECTL_CTX}" wait --for=condition=Ready nodes --all --timeout=180s

    log_info "Waiting for default service account..."
    for i in $(seq 1 60); do
        if kubectl --context "${KUBECTL_CTX}" get serviceaccount default -n default &>/dev/null; then
            return 0
        fi
        sleep 2
    done

    log_error "default/default service account was not created in time"
    kubectl --context "${KUBECTL_CTX}" get serviceaccount -A || true
    exit 1
}

wait_for_pod() {
    local pod=$1
    local purpose=$2

    log_info "Waiting for pod ${pod} (${purpose}, timeout ${POD_WAIT_TIMEOUT})..."
    if kubectl --context "${KUBECTL_CTX}" wait --for=condition=Ready "pod/${pod}" \
        --timeout="${POD_WAIT_TIMEOUT}" 2>/dev/null; then
        return 0
    fi

    local phase
    phase=$(kubectl --context "${KUBECTL_CTX}" get pod "${pod}" \
        -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
    if [ "${phase}" = "Running" ] || [ "${phase}" = "Succeeded" ]; then
        return 0
    fi

    log_error "pod ${pod} did not become ready (phase=${phase:-unknown})"
    kubectl --context "${KUBECTL_CTX}" describe pod "${pod}" || true
    docker logs "${ZOT_CONTAINER_NAME}" 2>&1 | tail -80 || true
    exit 1
}

evict_pause_image_from_node() {
    log_info "Evicting ${PAUSE_IMAGE} from kind node (kindest/node may pre-cache it)..."
    docker exec "${CONTROL_PLANE}" crictl rmi "${PAUSE_IMAGE}" 2>/dev/null || \
        log_info "Image was not cached on node (continuing)"
}

pause_tag_present() {
    echo "${1}" | jq -e --arg tag "3.10.1" '.tags | index($tag)' >/dev/null 2>&1
}

wait_for_pause_in_catalog() {
    local tags i

    for i in $(seq 1 90); do
        tags=$(curl -sf "http://localhost:${ZOT_HOST_PORT}/v2/pause/tags/list" 2>/dev/null || echo "")
        if pause_tag_present "${tags}"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# Match pause:3.10.1 skip/resync log lines (JSON "image"/"repo" fields or plain text).
pause_image_log_filter() {
    grep -E '(pause:3\.10\.1|"repo":"pause"|registry\.k8s\.io/pause)' || true
}

count_pause_skip_logs() {
    { grep "skipping image because it's already synced" || true; } \
        | pause_image_log_filter | wc -l | tr -d ' '
}

count_pause_resync_logs() {
    { grep "remote image digest changed, syncing again" || true; } \
        | pause_image_log_filter | wc -l | tr -d ' '
}

try_remove_container() {
    local name=$1
    local quiet=${2:-false}

    if ! docker container inspect "${name}" &>/dev/null; then
        return 0
    fi

    if [ "${quiet}" != "true" ]; then
        log_info "Removing container ${name}..."
    fi
    docker network disconnect kind "${name}" 2>/dev/null || true
    if docker rm -f "${name}" 2>/dev/null; then
        return 0
    fi

    if docker container inspect "${name}" &>/dev/null; then
        if [ "${quiet}" != "true" ]; then
            log_warn "Could not remove container ${name} (docker stop/rm failed)."
            log_warn "Orphans do not block this test (each run uses a unique name)."
        fi
        return 1
    fi
    return 0
}

remove_stale_kind_clusters() {
    local cluster

    while read -r cluster; do
        [ -n "${cluster}" ] || continue
        [ "${cluster}" = "${CLUSTER_NAME}" ] && continue
        case "${cluster}" in
            zot-sync-ondemand|zot-sync-ondemand-*)
                log_info "Removing stale kind cluster ${cluster}..."
                "${KIND}" delete cluster --name "${cluster}" 2>/dev/null || true
                ;;
        esac
    done < <("${KIND}" get clusters 2>/dev/null || true)
}

remove_stale_zot_containers() {
    local -a names=()
    local name count

    while read -r name; do
        [ -n "${name}" ] || continue
        [ "${name}" = "${ZOT_CONTAINER_NAME}" ] && continue
        case "${name}" in
            zot-sync-ondemand|zot-sync-ondemand-*)
                names+=("${name}")
                ;;
        esac
    done < <(docker ps -a --filter "name=zot-sync-ondemand" --format '{{.Names}}' 2>/dev/null || true)

    count=${#names[@]}
    [ "${count}" -eq 0 ] && return 0

    log_info "Removing ${count} leftover zot-sync-ondemand container(s)..."
    if ! try_remove_container "${names[0]}" true; then
        log_warn "Could not remove ${count} leftover container(s) (docker stop/rm failed)."
        log_warn "Orphans do not block this test (each run uses a unique name)."
        return 0
    fi

    for name in "${names[@]:1}"; do
        try_remove_container "${name}" true || true
    done
}

remove_stale_resources() {
    remove_stale_kind_clusters
    remove_stale_zot_containers
}

resolve_zot_host_port() {
    local mapped

    mapped=$(docker port "${ZOT_CONTAINER_NAME}" "${ZOT_LISTEN_PORT}/tcp" | head -1)
    ZOT_HOST_PORT=${mapped##*:}
    if [ -z "${ZOT_HOST_PORT}" ]; then
        log_error "Failed to resolve host port for ${ZOT_CONTAINER_NAME}"
        exit 1
    fi
}

cleanup() {
    local exit_code=$?
    set +o errexit
    log_info "Cleaning up..."
    if [ -n "${KUBECONFIG:-}" ]; then
        "${KIND}" delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
    fi
    try_remove_container "${ZOT_CONTAINER_NAME}" || true
    docker rmi -f "${ZOT_IMAGE}" 2>/dev/null || true
    rm -rf "${ZOT_STORAGE}" 2>/dev/null || true
    rm -f "${KUBECONFIG_FILE}" 2>/dev/null || true
    exit "${exit_code}"
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

# Use an isolated kubeconfig so kind does not modify ~/.kube/config.
log_info "Using isolated kubeconfig ${KUBECONFIG_FILE}"

# Remove leftovers from an interrupted prior run before doing any work.
remove_stale_resources

if [ ! -x "${ZOT_BINARY}" ]; then
    log_error "zot binary not found at ${ZOT_BINARY}."
    log_error "Build the extended binary (sync extension): make check-blackbox-prerequisites binary"
    exit 1
fi

# ---------------------------------------------------------------------------
# Build a minimal zot Docker image from the locally compiled binary and config.
# Config is baked into the image (not bind-mounted) because single-file bind
# mounts into distroless often become directories when the parent path is absent.
# Using gcr.io/distroless/base-debian12 (includes CA certificates) avoids a
# full recompile while still giving the image the TLS roots it needs to reach
# registry.k8s.io.
# ---------------------------------------------------------------------------
log_info "Building zot Docker image (${ZOT_IMAGE}) from local binary..."
BUILD_CTX=$(mktemp -d)
cp "${ZOT_BINARY}" "${BUILD_CTX}/zot"
cat > "${BUILD_CTX}/config.json" <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "/var/lib/registry"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${ZOT_LISTEN_PORT}"
    },
    "log": {
        "level": "info"
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
docker build \
    --platform "linux/${ARCH}" \
    -t "${ZOT_IMAGE}" \
    -f - "${BUILD_CTX}" <<DOCKER
FROM ${DISTROLESS_BASE_IMAGE}
COPY zot /usr/bin/zot
COPY config.json /config/config.json
ENTRYPOINT ["/usr/bin/zot"]
EXPOSE 5000
DOCKER
rm -rf "${BUILD_CTX}"
log_info "Image built: ${ZOT_IMAGE}"

mkdir -p "${ZOT_STORAGE}"

# ---------------------------------------------------------------------------
# Start the zot container (not yet on the kind network).
# ---------------------------------------------------------------------------
log_info "Starting zot container (${ZOT_CONTAINER_NAME})..."
docker run -d \
    --name "${ZOT_CONTAINER_NAME}" \
    -p "127.0.0.1::${ZOT_LISTEN_PORT}" \
    -v "${ZOT_STORAGE}:/var/lib/registry" \
    "${ZOT_IMAGE}" serve /config/config.json

resolve_zot_host_port
log_info "Zot listening on host port ${ZOT_HOST_PORT} (container port ${ZOT_LISTEN_PORT})"

log_info "Waiting for zot to be ready..."
for i in $(seq 1 30); do
    if curl -sf "http://localhost:${ZOT_HOST_PORT}/v2/" >/dev/null 2>&1; then
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
    endpoint = ["http://${ZOT_CONTAINER_NAME}:${ZOT_LISTEN_PORT}"]
EOF

# Connect the zot container to the kind Docker network so kind nodes can reach
# it by container name.
if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${ZOT_CONTAINER_NAME}")" = 'null' ]; then
    docker network connect kind "${ZOT_CONTAINER_NAME}"
fi

log_info "Cluster created; waiting for control plane..."
kubectl --context "${KUBECTL_CTX}" get nodes
wait_for_cluster_ready

# ---------------------------------------------------------------------------
# First pull: deploy a pod whose container image is pause:3.10.1.
# This causes the kind node's containerd to pull through the zot mirror.
# kindest/node often pre-loads pause; evict it so the pull must go through zot.
# ---------------------------------------------------------------------------
evict_pause_image_from_node

log_info "First pull: creating pod with image ${PAUSE_IMAGE}..."
kubectl --context "${KUBECTL_CTX}" run pause-first \
    --image="${PAUSE_IMAGE}" \
    --restart=Never \
    --image-pull-policy=Always

wait_for_pod pause-first "first pull; multi-arch sync may take a few minutes"
log_info "pause-first pod is ready"

log_info "Verifying pause:3.10.1 exists in zot catalog..."
if ! wait_for_pause_in_catalog; then
    TAGS=$(curl -sf "http://localhost:${ZOT_HOST_PORT}/v2/pause/tags/list" 2>/dev/null || echo "{}")
    log_error "pause:3.10.1 was not found in zot after first sync"
    echo "Tags response: ${TAGS}"
    docker logs "${ZOT_CONTAINER_NAME}"
    exit 1
fi
log_info "pause:3.10.1 confirmed in zot catalog"

LOGS_AFTER_FIRST=$(docker logs "${ZOT_CONTAINER_NAME}" 2>&1)
FIRST_PULL_SKIP_COUNT=$(echo "${LOGS_AFTER_FIRST}" | count_pause_skip_logs)
if [ "${FIRST_PULL_SKIP_COUNT}" -gt 0 ]; then
    log_error "FAIL: pause:3.10.1 was skipped on the first pull (expected a full sync)"
    echo "${LOGS_AFTER_FIRST}" \
        | { grep "skipping image because it's already synced" || true; } \
        | pause_image_log_filter | tail -10
    exit 1
fi

# ---------------------------------------------------------------------------
# Evict the image from the kind node's containerd image store so the next pod
# creation triggers a fresh pull request to zot (the skip-check path).
# ---------------------------------------------------------------------------
log_info "Removing pause-first pod and evicting image from kind node..."
kubectl --context "${KUBECTL_CTX}" delete pod pause-first --ignore-not-found=true
# Wait for pod to be fully gone before evicting image
kubectl --context "${KUBECTL_CTX}" wait --for=delete pod/pause-first --timeout=30s 2>/dev/null || true
evict_pause_image_from_node

# ---------------------------------------------------------------------------
# Second pull: re-create the pod.  The kind node pulls from zot again;  zot
# must recognise the image as already synced and skip re-downloading it from
# registry.k8s.io.
# ---------------------------------------------------------------------------
log_info "Second pull: creating pod with image ${PAUSE_IMAGE} (should be skipped by zot)..."
kubectl --context "${KUBECTL_CTX}" run pause-second \
    --image="${PAUSE_IMAGE}" \
    --restart=Never \
    --image-pull-policy=Always

wait_for_pod pause-second "second pull; expect zot skip, not upstream resync"
log_info "pause-second pod is ready"

# Give the zot container a moment to flush log buffers.
sleep 2

# ---------------------------------------------------------------------------
# Assert correct sync behaviour from zot logs.
# ---------------------------------------------------------------------------
ZOT_LOGS=$(docker logs "${ZOT_CONTAINER_NAME}" 2>&1)

log_info "=== Asserting zot sync behaviour ==="

SECOND_PULL_SKIP_COUNT=$(echo "${ZOT_LOGS}" | count_pause_skip_logs)
NEW_SKIP_COUNT=$((SECOND_PULL_SKIP_COUNT - FIRST_PULL_SKIP_COUNT))

# 1. The second pull must have been skipped (already synced).
if [ "${NEW_SKIP_COUNT}" -lt 1 ]; then
    log_error "FAIL: pause:3.10.1 was not skipped on the second pull"
    echo "=== Zot log excerpt (pause lines) ==="
    echo "${ZOT_LOGS}" \
        | { grep -iE 'pause|skipping image because' || true; } | tail -40
    exit 1
fi

# 2. The digest-change resync loop must NOT have occurred.
RESYNC_COUNT=$(echo "${ZOT_LOGS}" | count_pause_resync_logs)
if [ "${RESYNC_COUNT}" -gt 0 ]; then
    log_error "FAIL: pause:3.10.1 triggered a resync loop (issue #4184 regression)"
    echo "=== Zot log excerpt (resync lines) ==="
    echo "${ZOT_LOGS}" \
        | { grep "remote image digest changed" || true; } \
        | pause_image_log_filter | tail -20
    exit 1
fi

log_info "SUCCESS: ${PAUSE_IMAGE} synced without resync loop (issue #4184 verified fixed)"
