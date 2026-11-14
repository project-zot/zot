#!/usr/bin/env bash
# End-to-end test for the AgentRegistry -> Zot -> Kagent MCP server workflow.
#
# Creates a kind cluster, starts a local Zot registry on its Docker network,
# builds and pushes an arctl-generated MCP server image to Zot, registers its
# metadata in AgentRegistry, then deploys it through the KMCP controller.
#
# Usage:
#   make run-kind-agentregistry

set -o errexit
set -o pipefail

ROOT_DIR=$(git rev-parse --show-toplevel)
cd "${ROOT_DIR}"
export PATH="${ROOT_DIR}/hack/tools/bin:${PATH}"

ARCH=$(go env GOARCH)
ZOT_BINARY="${ROOT_DIR}/bin/zot-linux-${ARCH}"
KIND="${ROOT_DIR}/hack/tools/bin/kind"
ARCTL="${ROOT_DIR}/hack/tools/bin/arctl"
KMCP="${ROOT_DIR}/hack/tools/bin/kmcp"
AGENTREGISTRY_VERSION=${AGENTREGISTRY_VERSION:-v0.4.0}
KMCP_VERSION=${KMCP_VERSION:-v0.4.0}

if [ ! -x "${KIND}" ]; then
    KIND=$(command -v kind || true)
fi
if [ ! -x "${ARCTL}" ]; then
    ARCTL=$(command -v arctl || true)
fi
if [ ! -x "${KMCP}" ]; then
    KMCP=$(command -v kmcp || true)
fi

for cmd in docker kubectl helm curl jq python3 git; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "Error: ${cmd} is required but not found" >&2
        exit 1
    fi
done

if [ ! -x "${KIND}" ]; then
    echo "Error: kind is required; run 'make run-kind-agentregistry' to install it" >&2
    exit 1
fi
if [ ! -x "${ARCTL}" ]; then
    echo "Error: arctl is required; run 'make run-kind-agentregistry' to install it" >&2
    exit 1
fi
if [ ! -x "${KMCP}" ]; then
    echo "Error: kmcp is required; run 'make run-kind-agentregistry' to install it" >&2
    exit 1
fi

if [ ! -x "${ZOT_BINARY}" ]; then
    echo "Error: ${ZOT_BINARY} not found; run 'make OS=linux binary' first" >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker is unavailable; start the Docker daemon before running this test" >&2
    exit 1
fi

# kind v0.31.0's default node image (containerd 2.x); override to test other node versions.
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f}
ZOT_LISTEN_PORT=5000
RUN_SUFFIX="$(git rev-parse --short HEAD)-$$"
CLUSTER_NAME="zot-agentregistry-${RUN_SUFFIX}"
ZOT_CONTAINER_NAME="zot-agentregistry-${RUN_SUFFIX}"
ZOT_IMAGE="zot-agentregistry:${RUN_SUFFIX}"
MCP_NAME="zot-pipeline-test"
MCP_REPOSITORY="agentregistry-e2e/mcp-server"
MCP_TAG="0.1.0"
TMP_DIR=$(mktemp -d /tmp/zot-agentregistry-test-XXXXX)
KUBECONFIG_FILE="${TMP_DIR}/kubeconfig"
export KUBECONFIG="${KUBECONFIG_FILE}"
KUBECTL_CTX="kind-${CLUSTER_NAME}"
PORT_FORWARD_PID=""

log_info() { echo "[INFO] $*"; }
log_error() { echo "[ERROR] $*" >&2; }

get_free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

cleanup() {
    local exit_code=$?
    set +e

    if [ "${exit_code}" -ne 0 ] && [ -f "${KUBECONFIG_FILE}" ]; then
        kubectl --context "${KUBECTL_CTX}" get pods -A 2>/dev/null || true
        kubectl --context "${KUBECTL_CTX}" get events -A \
            --sort-by=.metadata.creationTimestamp 2>/dev/null | tail -60 || true
        kubectl --context "${KUBECTL_CTX}" describe mcpserver "${MCP_NAME}" 2>/dev/null || true
        kubectl --context "${KUBECTL_CTX}" logs "deployment/${MCP_NAME}" \
            -c mcp-server --tail=80 2>/dev/null || true
        kubectl --context "${KUBECTL_CTX}" logs -n kmcp-system \
            -l app.kubernetes.io/name=kmcp --tail=80 2>/dev/null || true
        kubectl --context "${KUBECTL_CTX}" logs -n agentregistry \
            -l app.kubernetes.io/instance=agentregistry --tail=80 2>/dev/null || true
        docker logs "${ZOT_CONTAINER_NAME}" 2>&1 | tail -80 || true
    fi
    if [ "${exit_code}" -ne 0 ] && [ -f "${TMP_DIR}/agentregistry-port-forward.log" ]; then
        cat "${TMP_DIR}/agentregistry-port-forward.log"
    fi

    if [ -n "${PORT_FORWARD_PID}" ]; then
        kill "${PORT_FORWARD_PID}" 2>/dev/null || true
        wait "${PORT_FORWARD_PID}" 2>/dev/null || true
    fi
    docker rm -f "${ZOT_CONTAINER_NAME}" >/dev/null 2>&1 || true
    "${KIND}" delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
    docker image rm -f "${ZOT_IMAGE}" \
        "localhost:${ZOT_HOST_PORT:-0}/${MCP_REPOSITORY}:${MCP_TAG}" >/dev/null 2>&1 || true
    rm -rf "${TMP_DIR}"
    exit "${exit_code}"
}
trap cleanup EXIT

ZOT_HOST_PORT=${ZOT_HOST_PORT:-$(get_free_port)}
AR_HOST_PORT=${AR_HOST_PORT:-$(get_free_port)}
while [ "${AR_HOST_PORT}" = "${ZOT_HOST_PORT}" ]; do
    AR_HOST_PORT=$(get_free_port)
done
MCP_IMAGE="localhost:${ZOT_HOST_PORT}/${MCP_REPOSITORY}:${MCP_TAG}"
BUILD_DIR="${TMP_DIR}/zot-image"
ZOT_CONFIG="${BUILD_DIR}/config.json"
mkdir -p "${BUILD_DIR}"

log_info "Building Zot image ${ZOT_IMAGE}..."
cp "${ZOT_BINARY}" "${BUILD_DIR}/zot"
cat >"${ZOT_CONFIG}" <<EOF
{
  "distSpecVersion": "1.1.1",
  "storage": {"rootDirectory": "/var/lib/registry"},
  "http": {"address": "0.0.0.0", "port": "${ZOT_LISTEN_PORT}", "compat": ["docker2s2"]},
  "log": {"level": "info"}
}
EOF
docker build --platform "linux/${ARCH}" -t "${ZOT_IMAGE}" -f - "${BUILD_DIR}" <<EOF
FROM gcr.io/distroless/base-nossl-debian13:latest-${ARCH}
COPY zot /usr/bin/zot
COPY config.json /etc/zot/config.json
ENTRYPOINT ["/usr/bin/zot"]
EXPOSE ${ZOT_LISTEN_PORT}
EOF

log_info "Creating kind cluster ${CLUSTER_NAME}..."
cat <<EOF | "${KIND}" create cluster --name "${CLUSTER_NAME}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: ${KIND_NODE_IMAGE}
# containerd 2.x rejects registry.mirrors once config_path is set (CRI fails to load and
# kubelet never starts), so route localhost:<port> to Zot through hosts.toml instead.
# Setting config_path explicitly keeps this working on containerd 1.7 node images too.
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry]
    config_path = "/etc/containerd/certs.d"
EOF
# containerd reads hosts.toml on each pull, so writing it after cluster creation needs no restart.
REGISTRY_DIR="/etc/containerd/certs.d/localhost:${ZOT_HOST_PORT}"
for node in $("${KIND}" get nodes --name "${CLUSTER_NAME}"); do
    docker exec "${node}" mkdir -p "${REGISTRY_DIR}"
    docker exec -i "${node}" cp /dev/stdin "${REGISTRY_DIR}/hosts.toml" <<EOF
[host."http://${ZOT_CONTAINER_NAME}:${ZOT_LISTEN_PORT}"]
  capabilities = ["pull", "resolve"]
EOF
done
kubectl --context "${KUBECTL_CTX}" wait --for=condition=Ready nodes --all --timeout=180s

log_info "Starting Zot on the kind network..."
docker run -d \
    --name "${ZOT_CONTAINER_NAME}" \
    --network kind \
    -p "127.0.0.1:${ZOT_HOST_PORT}:${ZOT_LISTEN_PORT}" \
    "${ZOT_IMAGE}" serve /etc/zot/config.json
for _ in $(seq 1 30); do
    if curl -fsS --connect-timeout 2 --max-time 5 "http://127.0.0.1:${ZOT_HOST_PORT}/v2/" >/dev/null; then
        break
    fi
    sleep 1
done
curl -fsS --connect-timeout 2 --max-time 5 "http://127.0.0.1:${ZOT_HOST_PORT}/v2/" >/dev/null

log_info "Installing AgentRegistry ${AGENTREGISTRY_VERSION}..."
helm upgrade --install agentregistry \
    oci://ghcr.io/agentregistry-dev/agentregistry/charts/agentregistry \
    --version "${AGENTREGISTRY_VERSION#v}" \
    --kube-context "${KUBECTL_CTX}" --namespace agentregistry --create-namespace \
    --wait --timeout 10m

log_info "Installing KMCP controller ${KMCP_VERSION}..."
"${KMCP}" install --version "${KMCP_VERSION#v}" --namespace kmcp-system
kubectl --context "${KUBECTL_CTX}" wait --for=condition=Available \
    deployment -l app.kubernetes.io/name=kmcp \
    --namespace kmcp-system --timeout=5m

AGENTREGISTRY_SERVICE=$(kubectl --context "${KUBECTL_CTX}" \
    --namespace agentregistry get services -o json |
    jq -r '.items[] | select(any(.spec.ports[]; .port == 12121)) | .metadata.name')
if [ -z "${AGENTREGISTRY_SERVICE}" ]; then
    log_error "Could not find AgentRegistry HTTP service on port 12121"
    exit 1
fi
kubectl --context "${KUBECTL_CTX}" --namespace agentregistry \
    port-forward --address 127.0.0.1 \
    "service/${AGENTREGISTRY_SERVICE}" "${AR_HOST_PORT}:12121" \
    >"${TMP_DIR}/agentregistry-port-forward.log" 2>&1 &
PORT_FORWARD_PID=$!

export ARCTL_API_BASE_URL="http://127.0.0.1:${AR_HOST_PORT}"
for _ in $(seq 1 60); do
    if ! kill -0 "${PORT_FORWARD_PID}" 2>/dev/null; then
        log_error "AgentRegistry port-forward exited before becoming reachable"
        exit 1
    fi
    if curl -fsS --connect-timeout 2 --max-time 5 "${ARCTL_API_BASE_URL}/v0/ping" >/dev/null; then
        break
    fi
    sleep 1
done
curl -fsS --connect-timeout 2 --max-time 5 "${ARCTL_API_BASE_URL}/v0/ping" >/dev/null

log_info "Scaffolding and publishing the MCP server to Zot..."
MCP_PROJECT="${TMP_DIR}/${MCP_NAME}"
"${ARCTL}" init --output-dir "${TMP_DIR}" mcp "${MCP_NAME}" \
    --framework fastmcp --language python \
    --image "${MCP_IMAGE}" --transport http
BUILDX_NO_DEFAULT_ATTESTATIONS=1 "${ARCTL}" build "${MCP_PROJECT}" --platform "linux/${ARCH}" --push

curl -fsS --max-time 10 "http://127.0.0.1:${ZOT_HOST_PORT}/v2/${MCP_REPOSITORY}/tags/list" |
    jq -e --arg tag "${MCP_TAG}" '.tags | index($tag) != null' >/dev/null

curl -fsS --max-time 10 -D "${TMP_DIR}/manifest.headers" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
    "http://127.0.0.1:${ZOT_HOST_PORT}/v2/${MCP_REPOSITORY}/manifests/${MCP_TAG}" \
    -o "${TMP_DIR}/manifest.json"
MCP_DIGEST=$(awk 'tolower($1) == "docker-content-digest:" {gsub("\r", "", $2); print $2}' "${TMP_DIR}/manifest.headers")
if [[ ! "${MCP_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    log_error "Zot did not return a valid manifest digest"
    exit 1
fi

log_info "Registering MCP metadata in AgentRegistry..."
"${ARCTL}" apply -f "${MCP_PROJECT}/mcp.yaml"
"${ARCTL}" get MCPServer "${MCP_NAME}" --output json >"${TMP_DIR}/registered-mcp.json"
jq -e --arg name "${MCP_NAME}" --arg image "${MCP_IMAGE}" \
    '.metadata.name == $name and
     .spec.source.package.origin.identifier == $image and
     .spec.source.package.transport.type == "http"' \
    "${TMP_DIR}/registered-mcp.json" >/dev/null

log_info "Deploying the registered MCP image through KMCP..."
# Consume the catalog record rather than independently re-declaring the image and launch settings.
jq '{
    apiVersion: "kagent.dev/v1alpha1",
    kind: "MCPServer",
    metadata: {name: .metadata.name, namespace: "default"},
    spec: {
        deployment: {
            image: .spec.source.package.origin.identifier,
            imagePullPolicy: "Always",
            cmd: .spec.source.package.launch.command,
            args: [.spec.source.package.launch.args[].value],
            port: .spec.source.package.transport.port
        },
        transportType: .spec.source.package.transport.type,
        httpTransport: {
            targetPort: .spec.source.package.transport.port,
            path: .spec.source.package.transport.path
        }
    }
}' "${TMP_DIR}/registered-mcp.json" >"${TMP_DIR}/kagent-mcpserver.json"
kubectl --context "${KUBECTL_CTX}" apply -f "${TMP_DIR}/kagent-mcpserver.json"
kubectl --context "${KUBECTL_CTX}" wait \
    --for=condition=Ready "mcpserver/${MCP_NAME}" \
    --namespace default --timeout=5m
kubectl --context "${KUBECTL_CTX}" get pods \
    -l "app.kubernetes.io/name=${MCP_NAME}" -o json |
    jq -e --arg image "${MCP_IMAGE}" --arg digest "${MCP_DIGEST}" \
        'any(.items[]; .status.phase == "Running" and
             any(.spec.containers[]; .name == "mcp-server" and .image == $image) and
             any(.status.containerStatuses[];
                 .name == "mcp-server" and .ready and (.imageID | endswith($digest))))' >/dev/null

log_info "Invoking an MCP tool on the deployed server..."
MCP_URL=$(jq -r '"http://\(.metadata.name).default.svc:\(.spec.source.package.transport.port)\(.spec.source.package.transport.path)"' \
    "${TMP_DIR}/registered-mcp.json")
kubectl --context "${KUBECTL_CTX}" exec -i "deployment/${MCP_NAME}" -c mcp-server -- python3 - "${MCP_URL}" <<'PY'
import asyncio
import sys
from urllib.parse import urlparse
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async def check():
    url = sys.argv[1]
    endpoint = urlparse(url)
    # Deployment availability can precede the Python server binding its socket.
    for attempt in range(30):
        try:
            _, writer = await asyncio.open_connection(endpoint.hostname, endpoint.port)
        except OSError:
            if attempt == 29:
                raise
            await asyncio.sleep(1)
        else:
            writer.close()
            await writer.wait_closed()
            break
    async with streamablehttp_client(url) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert any(tool.name == "example_echo" for tool in tools.tools), tools
            result = await session.call_tool("example_echo", {"message": "zot-pipeline-ok"})
            assert not result.isError, result
            assert any(getattr(item, "text", None) == "zot-pipeline-ok" for item in result.content), result

asyncio.run(asyncio.wait_for(check(), timeout=60))
PY

log_info "PASS: Zot stored ${MCP_IMAGE}, AgentRegistry registered it, and KMCP pulled ${MCP_DIGEST} and served an MCP tool call."
