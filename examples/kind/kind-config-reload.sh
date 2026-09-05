#!/bin/bash
# kind-config-reload.sh
#
# End-to-end test for config hot reload under a Kubernetes ConfigMap mount.
#
# kubelet updates a mounted ConfigMap through its AtomicWriter: a new payload
# directory is written and the ..data symlink is atomically retargeted, so the
# watched file never receives a Write event. The config reloader must pick the
# change up anyway (stat fingerprint polling) and apply the reloadable subset
# without a pod restart.
#
# This test:
#   1. Builds a minimal Docker image that packages the locally compiled zot binary.
#   2. Creates a kind cluster and deploys zot with its config in a ConfigMap and
#      htpasswd credentials in a Secret (both mounted as volumes, no subPath).
#   3. Asserts the initial accessControl: alice can list the catalog, bob gets 403.
#   4. Patches the ConfigMap to grant bob access.
#   5. Asserts zot logs the reload, bob's requests start succeeding, and the pod
#      was neither restarted nor recreated.
#
# Prerequisites:
#   make check-blackbox-prerequisites
#   make OS=linux binary
#
# Usage:
#   ./examples/kind/kind-config-reload.sh

set -o errexit
set -o pipefail

ROOT_DIR=$(git rev-parse --show-toplevel)
cd "${ROOT_DIR}"

# The image runs Linux regardless of the host, so the packaged binary must too.
ARCH=$(go env GOARCH)
ZOT_BINARY="${ROOT_DIR}/bin/zot-linux-${ARCH}"

if [ ! -x "${ZOT_BINARY}" ]; then
    echo "Error: ${ZOT_BINARY} not found. Run 'make OS=linux ARCH=${ARCH} binary' first." >&2
    exit 1
fi

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
POD_WAIT_TIMEOUT="180s"
# kubelet syncs mounted ConfigMaps on its own cadence (up to about a minute),
# then the reloader debounce fires; two minutes is a comfortable ceiling.
RELOAD_TIMEOUT_SECONDS=120

COMMIT_HASH=$(git describe --always --tags --long)
RUN_SUFFIX="$(git rev-parse --short HEAD)-$$"
CLUSTER_NAME="zot-config-reload-${RUN_SUFFIX}"
CONTROL_PLANE="${CLUSTER_NAME}-control-plane"
ZOT_IMAGE="zot-config-reload:${COMMIT_HASH}"
# Pinned digest for reproducible CI/nightly runs (index digest; docker --platform selects arch).
DISTROLESS_BASE_IMAGE="gcr.io/distroless/base-debian12@sha256:9c05cfd65f41c93a909ea67eb05b920a3b838780ea55df5421d48295d98ff957"

KUBECONFIG_FILE=$(mktemp /tmp/kind-config-reload-kubeconfig-XXXXX)
export KUBECONFIG="${KUBECONFIG_FILE}"

log_info()  { echo "[INFO]  $*"; }
log_error() { echo "[ERROR] $*" >&2; }

KUBECTL_CTX="kind-${CLUSTER_NAME}"

cleanup() {
    log_info "Cleaning up..."
    "${KIND}" delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
    docker rmi -f "${ZOT_IMAGE}" 2>/dev/null || true
    rm -f "${KUBECONFIG_FILE}"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Build a minimal zot Docker image from the locally compiled binary. The config
# is NOT baked in: it is mounted from a ConfigMap, which is the behavior under
# test.
# ---------------------------------------------------------------------------
log_info "Building zot Docker image (${ZOT_IMAGE}) from local binary..."
BUILD_CTX=$(mktemp -d)
cp "${ZOT_BINARY}" "${BUILD_CTX}/zot"
docker build \
    --platform "linux/${ARCH}" \
    -t "${ZOT_IMAGE}" \
    -f - "${BUILD_CTX}" <<DOCKER
FROM ${DISTROLESS_BASE_IMAGE}
COPY zot /usr/bin/zot
ENTRYPOINT ["/usr/bin/zot"]
EXPOSE ${ZOT_LISTEN_PORT}
DOCKER
rm -rf "${BUILD_CTX}"
log_info "Image built: ${ZOT_IMAGE}"

log_info "Creating kind cluster '${CLUSTER_NAME}'..."
EXISTING_CLUSTERS=$("${KIND}" get clusters 2>/dev/null || true)
if grep -qx "${CLUSTER_NAME}" <<<"${EXISTING_CLUSTERS}"; then
    "${KIND}" delete cluster --name "${CLUSTER_NAME}"
fi

cat <<EOF | "${KIND}" create cluster --name "${CLUSTER_NAME}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: ${KIND_NODE_IMAGE}
EOF

kubectl --context "${KUBECTL_CTX}" wait --for=condition=Ready nodes --all --timeout=180s

log_info "Loading ${ZOT_IMAGE} into the kind cluster..."
"${KIND}" load docker-image "${ZOT_IMAGE}" --name "${CLUSTER_NAME}"

# ---------------------------------------------------------------------------
# Deploy zot: config from a ConfigMap, htpasswd from a Secret, both mounted as
# whole volumes (subPath mounts are never updated by kubelet).
# ---------------------------------------------------------------------------
# bcrypt hashes for alice:alice and bob:bob (static so the test is
# deterministic; generated with htpasswd -nbB).
HTPASSWD='alice:$2y$05$dKbJtzXazxTrbI.4TmZLN.oSqM7np42T9tkCKdi0XDJ.LnjnSB55K
bob:$2y$05$UnHJ2xeU/SalnWRjqUf7UeuPG5Q/T4.fkKUBvpTtTPyl81wFw1DP.'

config_json() {
    local users=$1

    cat <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {"rootDirectory": "/var/lib/registry"},
    "http": {
        "address": "0.0.0.0",
        "port": "${ZOT_LISTEN_PORT}",
        "realm": "zot",
        "auth": {"htpasswd": {"path": "/etc/zot-auth/htpasswd"}, "failDelay": 1},
        "accessControl": {
            "repositories": {
                "**": {
                    "policies": [{"users": [${users}], "actions": ["read", "create"]}],
                    "defaultPolicy": []
                }
            }
        }
    },
    "log": {"level": "debug"}
}
EOF
}

log_info "Creating Secret, ConfigMap and Deployment..."
kubectl --context "${KUBECTL_CTX}" create secret generic zot-htpasswd \
    --from-literal=htpasswd="${HTPASSWD}"
kubectl --context "${KUBECTL_CTX}" create configmap zot-config \
    --from-literal=config.json="$(config_json '"alice"')"

cat <<EOF | kubectl --context "${KUBECTL_CTX}" apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zot
spec:
  replicas: 1
  selector:
    matchLabels: {app: zot}
  template:
    metadata:
      labels: {app: zot}
    spec:
      containers:
      - name: zot
        image: ${ZOT_IMAGE}
        imagePullPolicy: Never
        args: ["serve", "/etc/zot/config.json"]
        ports:
        - containerPort: ${ZOT_LISTEN_PORT}
        volumeMounts:
        - {name: config, mountPath: /etc/zot, readOnly: true}
        - {name: htpasswd, mountPath: /etc/zot-auth, readOnly: true}
        - {name: data, mountPath: /var/lib/registry}
      volumes:
      - name: config
        configMap: {name: zot-config}
      - name: htpasswd
        secret: {secretName: zot-htpasswd}
      - name: data
        emptyDir: {}
EOF

kubectl --context "${KUBECTL_CTX}" wait --for=condition=Available deployment/zot \
    --timeout="${POD_WAIT_TIMEOUT}"

POD=$(kubectl --context "${KUBECTL_CTX}" get pods -l app=zot -o jsonpath='{.items[0].metadata.name}')
POD_UID=$(kubectl --context "${KUBECTL_CTX}" get pod "${POD}" -o jsonpath='{.metadata.uid}')
log_info "zot pod: ${POD}"

kubectl --context "${KUBECTL_CTX}" port-forward deployment/zot "13000:${ZOT_LISTEN_PORT}" &
PF_PID=$!
trap 'kill ${PF_PID} 2>/dev/null || true; cleanup' EXIT
sleep 3

# Probe a repo-scoped endpoint: the catalog is filtered per user (an
# unauthorized user gets an empty 200), while tags/list is denied outright.
# An authorized user gets 404 for the nonexistent repo, a denied one gets 403.
tags_status() {
    local user=$1 pass=$2
    curl -s -o /dev/null -w '%{http_code}' -u "${user}:${pass}" \
        "http://127.0.0.1:13000/v2/testrepo/tags/list" || true
}

log_info "Asserting initial accessControl (alice authorized, bob denied)..."
for i in $(seq 1 30); do
    [ "$(tags_status alice alice)" = "404" ] && break
    sleep 2
done
[ "$(tags_status alice alice)" = "404" ] || { log_error "alice is not authorized (got $(tags_status alice alice))"; exit 1; }
[ "$(tags_status bob bob)" = "403" ] || { log_error "bob was not denied before the change (got $(tags_status bob bob))"; exit 1; }

log_info "Patching the ConfigMap to grant bob access (kubelet AtomicWriter update)..."
kubectl --context "${KUBECTL_CTX}" create configmap zot-config \
    --from-literal=config.json="$(config_json '"alice", "bob"')" \
    --dry-run=client -o yaml | kubectl --context "${KUBECTL_CTX}" replace -f -

log_info "Waiting up to ${RELOAD_TIMEOUT_SECONDS}s for the reload to land..."
DEADLINE=$(( $(date +%s) + RELOAD_TIMEOUT_SECONDS ))
RELOADED=0
while [ "$(date +%s)" -lt "${DEADLINE}" ]; do
    if [ "$(tags_status bob bob)" = "404" ]; then
        RELOADED=1
        break
    fi
    sleep 3
done

# Capture the logs once, then feed them to matchers as here-strings. Any
# producer piped into grep -q trips pipefail via SIGPIPE when grep exits on the
# first match and the producer is still writing.
ZOT_LOGS=$(kubectl --context "${KUBECTL_CTX}" logs "${POD}")

log_info "zot logs (reload lines):"
grep -E "config file changed|reloaded params" <<<"${ZOT_LOGS}" || true

if [ "${RELOADED}" != "1" ]; then
    log_error "bob still denied after ${RELOAD_TIMEOUT_SECONDS}s; config reload did not happen"
    tail -40 <<<"${ZOT_LOGS}"
    exit 1
fi

grep -q "config file changed" <<<"${ZOT_LOGS}" || {
    log_error "reload log line missing even though authorization changed"
    exit 1
}

log_info "Asserting the pod was neither restarted nor recreated..."
POD_NOW=$(kubectl --context "${KUBECTL_CTX}" get pods -l app=zot -o jsonpath='{.items[0].metadata.name}')
POD_UID_NOW=$(kubectl --context "${KUBECTL_CTX}" get pod "${POD_NOW}" -o jsonpath='{.metadata.uid}')
RESTARTS=$(kubectl --context "${KUBECTL_CTX}" get pod "${POD_NOW}" \
    -o jsonpath='{.status.containerStatuses[0].restartCount}')

if [ "${POD_UID_NOW}" != "${POD_UID}" ] || [ "${RESTARTS}" != "0" ]; then
    log_error "pod changed or restarted (uid ${POD_UID} -> ${POD_UID_NOW}, restarts ${RESTARTS})"
    exit 1
fi

log_info "PASS: ConfigMap update reloaded accessControl live, zero pod restarts."
