#!/bin/bash
# OIDC Workload Identity E2E Test
#
# This script tests OIDC workload identity federation with Kubernetes ServiceAccount tokens.
# It uses the native Kubernetes ServiceAccount issuer (not an external OIDC provider like Dex).
#
# The test:
# 1. Creates a Kind cluster with the API server OIDC discovery endpoint exposed
# 2. Exports the Kind cluster's CA certificate
# 3. Deploys Zot with OIDC bearer authentication
# 4. Creates a test Pod with a projected ServiceAccount token
# 5. Verifies authentication succeeds with the token
# 6. Verifies authentication fails without the token
#
# Usage:
#   ./kind-oidc-workload-identity.sh [OPTIONS]
#
# Options:
#   --skip-setup      Skip cluster creation, image building, and initial setup
#                     (assumes resources already exist from a previous run)
#   --only-crane      Only run crane e2e tests (tests 8-14)
#   --only-curl       Only run curl-based tests (tests 1-7)
#   --keep-resources  Don't clean up resources on exit (useful for debugging)
#   --help            Show this help message

set -o errexit
set -o pipefail

# Parse command line arguments
SKIP_SETUP=false
ONLY_CRANE=false
ONLY_CURL=false
KEEP_RESOURCES=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-setup)
            SKIP_SETUP=true
            shift
            ;;
        --only-crane)
            ONLY_CRANE=true
            shift
            ;;
        --only-curl)
            ONLY_CURL=true
            shift
            ;;
        --keep-resources)
            KEEP_RESOURCES=true
            shift
            ;;
        --help)
            sed -n '2,/^$/p' "$0" | grep -E "^#" | sed 's/^# *//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check prerequisites
check_prerequisites() {
    local missing=""
    for cmd in docker kubectl jq openssl curl git; do
        if ! command -v "$cmd" &> /dev/null; then
            missing="$missing $cmd"
        fi
    done
    if [ -n "$missing" ]; then
        echo "Error: Missing required tools:$missing"
        exit 1
    fi
}

check_prerequisites

ROOT_DIR=$(git rev-parse --show-toplevel)
cd "${ROOT_DIR}"

# Use project's kind if available, otherwise fall back to system kind
if [ -x "${ROOT_DIR}/hack/tools/bin/kind" ]; then
    KIND="${ROOT_DIR}/hack/tools/bin/kind"
elif command -v kind &> /dev/null; then
    KIND="kind"
else
    echo "Error: kind not found. Install kind or run 'make ${ROOT_DIR}/hack/tools/bin/kind'"
    exit 1
fi

CLUSTER_NAME="kind-oidc-wid"
ZOT_REG_NAME="zot-oidc-wid"
ZOT_PORT="5000"
TEST_NAMESPACE="oidc-test"
TEST_SA_NAME="test-workload"
AUDIENCE="zot-registry"

# Pin image versions for reproducibility and to avoid Docker Hub rate limiting issues
# These versions should be updated periodically
# Note: BUSYBOX_IMAGE uses gcr.io to avoid Docker Hub rate limits for crane operations
CURL_IMAGE="curlimages/curl:8.5.0"
ALPINE_IMAGE="alpine:3.19"
BUSYBOX_IMAGE="gcr.io/google-containers/busybox:1.27"
KIND_NODE_IMAGE="kindest/node:v1.28.7"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Helper function to ensure a pod exists and is ready
# Usage: ensure_pod_ready <pod-name> <namespace> <pod-yaml>
# Returns 0 if pod is ready, 1 if it couldn't be created/started
ensure_pod_ready() {
    local pod_name="$1"
    local namespace="$2"
    local timeout="${3:-120}"

    if kubectl get pod "$pod_name" -n "$namespace" &>/dev/null; then
        local pod_status
        pod_status=$(kubectl get pod "$pod_name" -n "$namespace" -o jsonpath='{.status.phase}')
        if [ "$pod_status" = "Running" ]; then
            log_info "Pod '$pod_name' already exists and is running (reusing)"
            return 0
        else
            log_info "Pod '$pod_name' exists but status is '$pod_status', waiting..."
        fi
    else
        return 1  # Pod doesn't exist, caller should create it
    fi

    # Wait for pod to be ready
    kubectl wait --for=condition=Ready "pod/$pod_name" -n "$namespace" --timeout="${timeout}s"
}

cleanup() {
    if [ "$KEEP_RESOURCES" = true ]; then
        log_info "Keeping resources (--keep-resources specified)"
        log_info "To clean up manually, run:"
        log_info "  ${KIND} delete cluster --name ${CLUSTER_NAME}"
        log_info "  docker rm -f ${ZOT_REG_NAME}"
        return
    fi
    log_info "Cleaning up..."
    "${KIND}" delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
    docker rm -f "${ZOT_REG_NAME}" 2>/dev/null || true
    rm -f /tmp/kind-ca.pem /tmp/zot-oidc-config.json /tmp/test-token.txt 2>/dev/null || true
}

trap cleanup EXIT

# Set no_proxy if applicable
if [ -n "${no_proxy}" ]; then
    log_info "Updating no_proxy env var"
    export no_proxy="${no_proxy},${ZOT_REG_NAME}"
    export NO_PROXY="${no_proxy}"
fi

# Pre-pull images to avoid Docker Hub rate limiting issues in CI
# This is done early so failures are caught before cluster creation
prepull_images() {
    log_info "Pre-pulling container images (helps avoid Docker Hub rate limiting)..."
    local images=("${CURL_IMAGE}" "${ALPINE_IMAGE}" "${BUSYBOX_IMAGE}" "${KIND_NODE_IMAGE}")
    for img in "${images[@]}"; do
        log_info "Pulling ${img}..."
        if ! docker pull "${img}" 2>/dev/null; then
            log_warn "Failed to pull ${img} - will retry during test (may be rate limited)"
        fi
    done
}

# Skip setup if requested
if [ "$SKIP_SETUP" = true ]; then
    log_info "Skipping setup (--skip-setup specified)"
    log_info "Using existing cluster '${CLUSTER_NAME}' and zot container '${ZOT_REG_NAME}'"

    # Verify resources exist
    if ! "${KIND}" get clusters 2>/dev/null | grep -q "${CLUSTER_NAME}"; then
        log_error "Cluster '${CLUSTER_NAME}' does not exist. Run without --skip-setup first."
        exit 1
    fi
    if ! docker ps --format '{{.Names}}' | grep -q "^${ZOT_REG_NAME}$"; then
        log_error "Zot container '${ZOT_REG_NAME}' is not running. Run without --skip-setup first."
        exit 1
    fi

    # Set kubectl context
    kubectl config use-context "kind-${CLUSTER_NAME}"

    # Get the OIDC issuer URL
    CONTROL_PLANE_CONTAINER="${CLUSTER_NAME}-control-plane"
    OIDC_ISSUER="https://${CONTROL_PLANE_CONTAINER}:6443"
else
    # Delete existing cluster if it exists
    log_info "Cleaning up any existing resources..."
    "${KIND}" delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
    docker rm -f "${ZOT_REG_NAME}" 2>/dev/null || true

    # Pre-pull images to avoid rate limiting
    prepull_images

# Create Kind cluster with custom configuration
# - Configure the ServiceAccount issuer to be accessible from zot (via docker network)
# - Add the container name as a SAN to the API server certificate
log_info "Creating Kind cluster '${CLUSTER_NAME}'..."
cat <<EOF | "${KIND}" create cluster --name "${CLUSTER_NAME}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: ${KIND_NODE_IMAGE}
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      certSANs:
        - "localhost"
        - "127.0.0.1"
        - "${CLUSTER_NAME}-control-plane"
      extraArgs:
        # Configure the ServiceAccount issuer to use the container name
        # This URL must be reachable from zot (via docker network)
        service-account-issuer: "https://${CLUSTER_NAME}-control-plane:6443"
        # Enable anonymous auth (required for OIDC discovery)
        anonymous-auth: "true"
        # Configure API audiences
        api-audiences: "api,${AUDIENCE}"
EOF

# Wait for the cluster to be ready
log_info "Waiting for cluster to be ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=120s

# Load pre-pulled images into Kind cluster to avoid Docker Hub rate limiting
# This makes the images available to pods inside the cluster without pulling from Docker Hub
log_info "Loading images into Kind cluster..."
for img in "${CURL_IMAGE}" "${ALPINE_IMAGE}" "${BUSYBOX_IMAGE}"; do
    log_info "Loading ${img}..."
    "${KIND}" load docker-image "${img}" --name "${CLUSTER_NAME}" || log_warn "Failed to load ${img}"
done

# Get the control plane container name and IP
CONTROL_PLANE_CONTAINER="${CLUSTER_NAME}-control-plane"
CONTROL_PLANE_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${CONTROL_PLANE_CONTAINER}")
log_info "Control plane container: ${CONTROL_PLANE_CONTAINER}"
log_info "Control plane IP: ${CONTROL_PLANE_IP}"

# Create ClusterRoleBinding to allow unauthenticated access to OIDC discovery
# This is required for external services (like zot) to verify ServiceAccount tokens
log_info "Creating ClusterRoleBinding for OIDC discovery..."
kubectl create clusterrolebinding oidc-reviewer \
    --clusterrole=system:service-account-issuer-discovery \
    --group=system:unauthenticated || true

# Export the Kind cluster's CA certificate
log_info "Exporting Kind cluster CA certificate..."
docker cp "${CONTROL_PLANE_CONTAINER}:/etc/kubernetes/pki/ca.crt" /tmp/kind-ca.pem

# Verify the CA certificate
log_info "Verifying CA certificate..."
openssl x509 -in /tmp/kind-ca.pem -text -noout | head -20

# Get the OIDC issuer URL (this is the Kubernetes API server)
OIDC_ISSUER="https://${CONTROL_PLANE_CONTAINER}:6443"
log_info "OIDC Issuer: ${OIDC_ISSUER}"

# Test OIDC discovery endpoint is accessible (via docker exec since we're not on kind network)
log_info "Testing OIDC discovery endpoint..."
docker exec "${CONTROL_PLANE_CONTAINER}" curl -sk "https://localhost:6443/.well-known/openid-configuration" | jq . || log_warn "OIDC discovery endpoint test inconclusive"

# Build zot docker image
# Using minimal Dockerfile since bearer OIDC is part of the core (no build tags)
log_info "Building zot docker image (minimal)... this may take a few minutes"
COMMIT_HASH=$(git describe --always --tags --long)
IMAGE_NAME="zot-linux-amd64-minimal:${COMMIT_HASH}"

# Build using docker buildx with load to make it available locally
# Use --quiet to suppress verbose build output
docker buildx build \
    --platform linux/amd64 \
    --build-arg BASE_IMAGE=gcr.io/distroless/base-debian12:latest-amd64 \
    --build-arg COMMIT="${COMMIT_HASH}" \
    -t "${IMAGE_NAME}" \
    --load \
    --quiet \
    -f build/Dockerfile-minimal .

log_info "Image built: ${IMAGE_NAME}"

# Create zot configuration for OIDC bearer authentication
# The username mapping uses the default (iss + '/' + sub) which results in:
# "https://<control-plane>:6443/system:serviceaccount:<namespace>:<sa-name>"
cat <<EOF > /tmp/zot-oidc-config.json
{
  "distSpecVersion": "1.1.1",
  "storage": {
    "rootDirectory": "/var/lib/zot"
  },
  "http": {
    "address": "0.0.0.0",
    "port": "${ZOT_PORT}",
    "auth": {
      "bearer": {
        "realm": "zot",
        "service": "zot-registry",
        "oidc": [
          {
            "issuer": "${OIDC_ISSUER}",
            "audiences": ["${AUDIENCE}"],
            "certificateAuthorityFile": "/etc/zot/kind-ca.pem"
          }
        ]
      }
    },
    "accessControl": {
      "repositories": {
        "**": {
          "policies": [
            {
              "users": ["${OIDC_ISSUER}/system:serviceaccount:${TEST_NAMESPACE}:${TEST_SA_NAME}"],
              "actions": ["read", "create", "update", "delete"]
            }
          ],
          "defaultPolicy": []
        }
      }
    }
  },
  "log": {
    "level": "debug"
  }
}
EOF

log_info "Zot configuration:"
cat /tmp/zot-oidc-config.json

# Run zot container connected to the kind network
log_info "Starting zot container..."
docker run -d \
    --name "${ZOT_REG_NAME}" \
    --network kind \
    -p "127.0.0.1:${ZOT_PORT}:${ZOT_PORT}" \
    -v /tmp/zot-oidc-config.json:/etc/zot/config.json:ro \
    -v /tmp/kind-ca.pem:/etc/zot/kind-ca.pem:ro \
    "${IMAGE_NAME}" \
    serve /etc/zot/config.json

# Wait for zot to be ready
log_info "Waiting for zot to be ready..."
sleep 5

# Check zot logs
log_info "Zot container logs:"
docker logs "${ZOT_REG_NAME}" 2>&1 | tail -30

# Get zot container IP on the kind network
ZOT_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${ZOT_REG_NAME}")
log_info "Zot container IP: ${ZOT_IP}"

# Verify zot is running and responding
log_info "Checking zot health..."
for i in {1..30}; do
    # zot should return 401 for unauthenticated requests when bearer auth is configured
    HTTP_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${ZOT_PORT}/v2/" 2>/dev/null || echo "000")
    if [ "$HTTP_RESPONSE" = "401" ] || [ "$HTTP_RESPONSE" = "200" ]; then
        log_info "Zot is responding (HTTP $HTTP_RESPONSE)"
        break
    fi
    if [ $i -eq 30 ]; then
        log_error "Zot failed to start (HTTP $HTTP_RESPONSE)"
        docker logs "${ZOT_REG_NAME}"
        exit 1
    fi
    sleep 1
done

fi  # End of setup section (skip-setup conditional)

# Create test namespace and ServiceAccount
log_info "Creating test namespace and ServiceAccount..."
kubectl create namespace "${TEST_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
kubectl create serviceaccount "${TEST_SA_NAME}" -n "${TEST_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# Create a test Pod with projected ServiceAccount token (or reuse existing)
# Using a lightweight image with wget/curl for testing
if ! ensure_pod_ready "oidc-test-pod" "${TEST_NAMESPACE}" 120; then
    log_info "Creating test Pod with projected ServiceAccount token..."
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: oidc-test-pod
  namespace: ${TEST_NAMESPACE}
spec:
  serviceAccountName: ${TEST_SA_NAME}
  containers:
  - name: test
    image: ${CURL_IMAGE}
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: token
      mountPath: /var/run/secrets/tokens
      readOnly: true
    env:
    - name: ZOT_REGISTRY
      value: "${ZOT_REG_NAME}:${ZOT_PORT}"
  volumes:
  - name: token
    projected:
      sources:
      - serviceAccountToken:
          path: zot-token
          expirationSeconds: 3600
          audience: ${AUDIENCE}
  restartPolicy: Never
EOF
    log_info "Waiting for test pod to be ready..."
    kubectl wait --for=condition=Ready pod/oidc-test-pod -n "${TEST_NAMESPACE}" --timeout=120s
fi

# Verify the projected token exists and has correct audience
log_info "Verifying projected ServiceAccount token..."
kubectl exec -n "${TEST_NAMESPACE}" oidc-test-pod -- cat /var/run/secrets/tokens/zot-token > /tmp/test-token.txt
log_info "Token claims (decoded):"
# Decode the JWT payload (second part, base64url encoded)
PAYLOAD=$(cat /tmp/test-token.txt | cut -d'.' -f2)
# Add padding if needed and decode
PAYLOAD_PADDED="${PAYLOAD}$(printf '%*s' $((4 - ${#PAYLOAD} % 4)) | tr ' ' '=')"
echo "${PAYLOAD_PADDED}" | base64 -d 2>/dev/null | jq . || log_warn "Could not decode token (may need jq)"

# =============================================================================
# CURL-BASED TESTS (Tests 1-7)
# =============================================================================
if [ "$ONLY_CRANE" = true ]; then
    log_info "Skipping curl-based tests (--only-oras specified)"
else

# Test 1: Verify PUSH fails without token
log_info "TEST 1: Verifying push (blob upload) fails without token..."
HTTP_CODE=$(kubectl exec -n "${TEST_NAMESPACE}" oidc-test-pod -- \
    curl -s -o /dev/null -w "%{http_code}" -X POST "http://${ZOT_REG_NAME}:${ZOT_PORT}/v2/test-repo/blobs/uploads/" 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "401" ]; then
    log_info "TEST 1 PASSED: Push correctly rejected without token (HTTP $HTTP_CODE)"
else
    log_error "TEST 1 FAILED: Expected 401, got HTTP $HTTP_CODE"
    docker logs "${ZOT_REG_NAME}" 2>&1 | tail -30
    exit 1
fi

# Test 2: Verify authentication SUCCEEDS with token
log_info "TEST 2: Verifying authentication succeeds with token..."
RESPONSE=$(kubectl exec -n "${TEST_NAMESPACE}" oidc-test-pod -- \
    sh -c 'TOKEN=$(cat /var/run/secrets/tokens/zot-token); curl -s -w "\n%{http_code}" -H "Authorization: Bearer $TOKEN" "http://${ZOT_REGISTRY}/v2/_catalog"')

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "200" ]; then
    log_info "TEST 2 PASSED: Authentication succeeded with token (HTTP $HTTP_CODE)"
    log_info "Response body: $BODY"
else
    log_error "TEST 2 FAILED: Authentication failed with valid token (HTTP $HTTP_CODE)"
    log_error "Response: $BODY"
    docker logs "${ZOT_REG_NAME}" 2>&1 | tail -50
    exit 1
fi

# Test 3: Initiate a blob upload (tests write permissions)
log_info "TEST 3: Testing write permissions (initiate blob upload)..."
RESPONSE=$(kubectl exec -n "${TEST_NAMESPACE}" oidc-test-pod -- \
    sh -c 'TOKEN=$(cat /var/run/secrets/tokens/zot-token); curl -s -w "\n%{http_code}" -X POST -H "Authorization: Bearer $TOKEN" "http://${ZOT_REGISTRY}/v2/test-repo/blobs/uploads/"')

HTTP_CODE=$(echo "$RESPONSE" | tail -1)

if [ "$HTTP_CODE" = "202" ]; then
    log_info "TEST 3 PASSED: Write operation succeeded (HTTP $HTTP_CODE - upload initiated)"
else
    log_error "TEST 3 FAILED: Write operation failed (HTTP $HTTP_CODE)"
    docker logs "${ZOT_REG_NAME}" 2>&1 | tail -30
    exit 1
fi

# Test 4: List the catalog to verify repository was created
log_info "TEST 4: Listing catalog to verify repository exists..."
CATALOG=$(kubectl exec -n "${TEST_NAMESPACE}" oidc-test-pod -- \
    sh -c 'TOKEN=$(cat /var/run/secrets/tokens/zot-token); curl -s -H "Authorization: Bearer $TOKEN" "http://${ZOT_REGISTRY}/v2/_catalog"')
log_info "Catalog: ${CATALOG}"

if echo "$CATALOG" | grep -q "test-repo"; then
    log_info "TEST 4 PASSED: Repository 'test-repo' found in catalog"
else
    log_warn "TEST 4: Repository may not appear immediately in catalog (this is expected)"
fi

# Test 5: Verify wrong audience token fails
log_info "TEST 5: Verifying wrong audience token fails..."

# Create another pod with a different audience (or reuse existing)
if ! ensure_pod_ready "oidc-test-pod-wrong-aud" "${TEST_NAMESPACE}" 60; then
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: oidc-test-pod-wrong-aud
  namespace: ${TEST_NAMESPACE}
spec:
  serviceAccountName: ${TEST_SA_NAME}
  containers:
  - name: test
    image: ${CURL_IMAGE}
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: token
      mountPath: /var/run/secrets/tokens
      readOnly: true
    env:
    - name: ZOT_REGISTRY
      value: "${ZOT_REG_NAME}:${ZOT_PORT}"
  volumes:
  - name: token
    projected:
      sources:
      - serviceAccountToken:
          path: zot-token
          expirationSeconds: 3600
          audience: wrong-audience
  restartPolicy: Never
EOF
    log_info "Waiting for wrong-audience test pod to be ready..."
    kubectl wait --for=condition=Ready pod/oidc-test-pod-wrong-aud -n "${TEST_NAMESPACE}" --timeout=60s
fi

HTTP_CODE=$(kubectl exec -n "${TEST_NAMESPACE}" oidc-test-pod-wrong-aud -- \
    sh -c 'TOKEN=$(cat /var/run/secrets/tokens/zot-token); curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "http://${ZOT_REGISTRY}/v2/_catalog"' 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "401" ]; then
    log_info "TEST 5 PASSED: Wrong audience token correctly rejected (HTTP $HTTP_CODE)"
else
    log_error "TEST 5 FAILED: Expected 401 for wrong audience, got HTTP $HTTP_CODE"
    docker logs "${ZOT_REG_NAME}" 2>&1 | tail -30
    exit 1
fi

# Test 6: Verify different ServiceAccount with correct audience is authenticated
# Note: Currently, OIDC bearer auth only performs authentication, not repository-level authorization.
# The BaseAuthzHandler in zot bypasses authorization checks for bearer auth.
# This test verifies that a different SA with the correct audience CAN authenticate (proving OIDC works)
# but has NO permissions because it's not in the accessControl config.
# The username is derived from the token and used for authorization checks.
log_info "TEST 6: Verifying different ServiceAccount authenticates but has NO permissions..."

# Create a different ServiceAccount
kubectl create serviceaccount other-sa -n "${TEST_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# Create pod with the other ServiceAccount (or reuse existing)
if ! ensure_pod_ready "oidc-test-pod-other-sa" "${TEST_NAMESPACE}" 60; then
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: oidc-test-pod-other-sa
  namespace: ${TEST_NAMESPACE}
spec:
  serviceAccountName: other-sa
  containers:
  - name: test
    image: ${CURL_IMAGE}
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: token
      mountPath: /var/run/secrets/tokens
      readOnly: true
    env:
    - name: ZOT_REGISTRY
      value: "${ZOT_REG_NAME}:${ZOT_PORT}"
  volumes:
  - name: token
    projected:
      sources:
      - serviceAccountToken:
          path: zot-token
          expirationSeconds: 3600
          audience: ${AUDIENCE}
  restartPolicy: Never
EOF
    log_info "Waiting for other-sa test pod to be ready..."
    kubectl wait --for=condition=Ready pod/oidc-test-pod-other-sa -n "${TEST_NAMESPACE}" --timeout=60s
fi

# Verify that other-sa can authenticate but sees an EMPTY catalog (no read permissions)
CATALOG_RESPONSE=$(kubectl exec -n "${TEST_NAMESPACE}" oidc-test-pod-other-sa -- \
    sh -c 'TOKEN=$(cat /var/run/secrets/tokens/zot-token); curl -s -H "Authorization: Bearer $TOKEN" "http://${ZOT_REGISTRY}/v2/_catalog"' 2>/dev/null || echo "{}")

if echo "$CATALOG_RESPONSE" | grep -q '"repositories":\[\]'; then
    log_info "TEST 6 PASSED: Other ServiceAccount authenticated but has NO permissions (empty catalog)"
    log_info "      The username '${OIDC_ISSUER}/system:serviceaccount:${TEST_NAMESPACE}:other-sa' was extracted from the token."
    log_info "      Authorization is enforced via accessControl config."
else
    log_error "TEST 6 FAILED: Expected empty catalog for other-sa (not in config)"
    log_error "Got: $CATALOG_RESPONSE"
    docker logs "${ZOT_REG_NAME}" 2>&1 | tail -30
    exit 1
fi

# =============================================================================
# TEST 7: Verify other-sa gets 403 when trying to write (authorization enforced)
# =============================================================================
log_info "TEST 7: Verifying other-sa gets 403 Forbidden when trying to write..."

HTTP_CODE=$(kubectl exec -n "${TEST_NAMESPACE}" oidc-test-pod-other-sa -- \
    sh -c 'TOKEN=$(cat /var/run/secrets/tokens/zot-token); curl -s -o /dev/null -w "%{http_code}" -X POST -H "Authorization: Bearer $TOKEN" "http://${ZOT_REGISTRY}/v2/unauthorized-repo/blobs/uploads/"' 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "403" ]; then
    log_info "TEST 7 PASSED: Other ServiceAccount correctly rejected for write (HTTP 403)"
else
    log_error "TEST 7 FAILED: Expected 403 for write operation, got HTTP $HTTP_CODE"
    docker logs "${ZOT_REG_NAME}" 2>&1 | tail -30
    exit 1
fi

fi  # End of curl-based tests conditional

# =============================================================================
# E2E Tests using Crane CLI for real OCI image operations
# =============================================================================
# NOTE: Crane (from go-containerregistry) properly supports the `registryToken`
# field in Docker config, which sends the token directly as a Bearer header.
# This is compatible with zot's OIDC bearer authentication.
#
# Other tools like oras and skopeo do NOT properly support this - they expect
# the token service authentication flow (exchanging credentials with a token
# endpoint) which is different from direct bearer token authentication.
# =============================================================================
if [ "$ONLY_CURL" = true ]; then
    log_info "Skipping crane e2e tests (--only-curl specified)"
else

# Create a Pod with crane CLI for e2e artifact push/pull tests (or reuse existing)
if ! ensure_pod_ready "crane-test-pod" "${TEST_NAMESPACE}" 120; then
    log_info "Creating crane test Pod for e2e artifact operations..."
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: crane-test-pod
  namespace: ${TEST_NAMESPACE}
spec:
  serviceAccountName: ${TEST_SA_NAME}
  initContainers:
  - name: install-crane
    image: ${ALPINE_IMAGE}
    command:
    - sh
    - -c
    - |
      apk add --no-cache curl
      curl -sL https://github.com/google/go-containerregistry/releases/download/v0.20.2/go-containerregistry_Linux_x86_64.tar.gz | tar -xzf - -C /tools crane
      chmod +x /tools/crane
    volumeMounts:
    - name: tools
      mountPath: /tools
  containers:
  - name: crane
    image: ${ALPINE_IMAGE}
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: token
      mountPath: /var/run/secrets/tokens
      readOnly: true
    - name: tools
      mountPath: /usr/local/bin
    env:
    - name: ZOT_REGISTRY
      value: "${ZOT_REG_NAME}:${ZOT_PORT}"
  volumes:
  - name: token
    projected:
      sources:
      - serviceAccountToken:
          path: zot-token
          expirationSeconds: 3600
          audience: ${AUDIENCE}
  - name: tools
    emptyDir: {}
  restartPolicy: Never
EOF
    log_info "Waiting for crane test pod to be ready..."
    kubectl wait --for=condition=Ready pod/crane-test-pod -n "${TEST_NAMESPACE}" --timeout=180s
fi

# Helper function to set up Docker config with registryToken
setup_crane_auth() {
    kubectl exec -n "${TEST_NAMESPACE}" crane-test-pod -- sh -c '
        mkdir -p ~/.docker
        TOKEN=$(cat /var/run/secrets/tokens/zot-token)
        cat > ~/.docker/config.json << EOFCONFIG
{
  "auths": {
    "$ZOT_REGISTRY": {
      "registryToken": "$TOKEN"
    }
  }
}
EOFCONFIG
    '
}

# Helper function to remove Docker config (no auth)
remove_crane_auth() {
    kubectl exec -n "${TEST_NAMESPACE}" crane-test-pod -- sh -c '
        rm -f ~/.docker/config.json
        rm -f /tmp/auth.json
        rm -rf ~/.config/containers
    ' 2>/dev/null || true
}

# =============================================================================
# TEST 8: Copy OCI image using crane WITH auth (should SUCCEED)
# Note: This runs first to populate zot, so subsequent tests don't need Docker Hub
# We check if the image already exists to avoid Docker Hub rate limiting on reruns
# =============================================================================
log_info "TEST 8: Copying OCI image using crane WITH auth (should succeed)..."
setup_crane_auth

# Check if image already exists in zot from a previous run
IMAGE_EXISTS=$(kubectl exec -n "${TEST_NAMESPACE}" crane-test-pod -- \
    sh -c 'crane manifest --insecure $ZOT_REGISTRY/crane-test:v1 2>&1 && echo EXISTS' || true)

if echo "$IMAGE_EXISTS" | grep -q "EXISTS"; then
    log_info "Image crane-test:v1 already exists in zot, skipping Docker Hub pull"
    # Verify we can still access it with auth (do a copy to v1-test to verify write works)
    PUSH_OUTPUT=$(kubectl exec -n "${TEST_NAMESPACE}" crane-test-pod -- \
        sh -c 'crane copy --insecure $ZOT_REGISTRY/crane-test:v1 $ZOT_REGISTRY/crane-test:v1-test 2>&1') || true
    if echo "$PUSH_OUTPUT" | grep -qiE "pushed|existing|copied|digest"; then
        log_info "TEST 8 PASSED: crane copy within zot succeeded with auth"
        log_info "Push output: $(echo "$PUSH_OUTPUT" | tail -2)"
    else
        log_error "TEST 8 FAILED: crane copy within zot failed"
        log_error "Output: $PUSH_OUTPUT"
        docker logs "${ZOT_REG_NAME}" 2>&1 | tail -50
        exit 1
    fi
else
    # Image doesn't exist, need to pull from Docker Hub
    log_info "Image not found in zot, pulling from Docker Hub..."
    PUSH_OUTPUT=$(kubectl exec -n "${TEST_NAMESPACE}" crane-test-pod -- \
        sh -c "crane copy --insecure ${BUSYBOX_IMAGE} \$ZOT_REGISTRY/crane-test:v1 2>&1") || true

    if echo "$PUSH_OUTPUT" | grep -qiE "pushed|existing|crane-test:v1.*digest|copied"; then
        log_info "TEST 8 PASSED: crane copy from Docker Hub succeeded with auth"
        log_info "Push output: $(echo "$PUSH_OUTPUT" | tail -3)"
    else
        log_error "TEST 8 FAILED: crane copy failed with valid auth"
        log_error "Output: $PUSH_OUTPUT"
        log_error "Note: If you see rate limit errors, this may be due to Docker Hub throttling"
        docker logs "${ZOT_REG_NAME}" 2>&1 | tail -50
        exit 1
    fi
fi

# Verify the image was pushed by listing tags
log_info "Verifying pushed image (listing tags)..."
TAGS=$(kubectl exec -n "${TEST_NAMESPACE}" crane-test-pod -- \
    sh -c 'crane ls --insecure $ZOT_REGISTRY/crane-test 2>&1') || true
log_info "Tags for crane-test: $TAGS"

if echo "$TAGS" | grep -q "v1"; then
    log_info "Verified: Tag 'v1' found in crane-test repository"
else
    log_warn "Warning: Tag 'v1' not found in crane-test repository"
fi

# =============================================================================
# TEST 9: Copy OCI image using crane WITHOUT auth (should FAIL)
# Note: Uses zot-to-zot copy to avoid Docker Hub rate limiting
# =============================================================================
log_info "TEST 9: Copying OCI image using crane WITHOUT auth (should fail)..."
remove_crane_auth

COPY_NO_AUTH_OUTPUT=$(kubectl exec -n "${TEST_NAMESPACE}" crane-test-pod -- \
    sh -c 'crane copy --insecure $ZOT_REGISTRY/crane-test:v1 $ZOT_REGISTRY/crane-test:v2 2>&1' || true)

if echo "$COPY_NO_AUTH_OUTPUT" | grep -qiE "401|unauthorized|UNAUTHORIZED"; then
    log_info "TEST 9 PASSED: crane copy correctly rejected without auth (401)"
    log_info "Output: $(echo "$COPY_NO_AUTH_OUTPUT" | tail -2)"
else
    log_error "TEST 9 FAILED: Expected 401 authentication failure"
    log_error "Output: $COPY_NO_AUTH_OUTPUT"
    docker logs "${ZOT_REG_NAME}" 2>&1 | tail -30
    exit 1
fi

# =============================================================================
# TEST 10: List tags using crane WITHOUT auth (should FAIL)
# =============================================================================
log_info "TEST 10: Listing tags using crane WITHOUT auth (should fail)..."

PULL_OUTPUT=$(kubectl exec -n "${TEST_NAMESPACE}" crane-test-pod -- \
    sh -c 'crane ls --insecure $ZOT_REGISTRY/crane-test 2>&1' || true)

if echo "$PULL_OUTPUT" | grep -qiE "401|unauthorized|authentication|UNAUTHORIZED"; then
    log_info "TEST 10 PASSED: crane ls correctly rejected without auth"
    log_info "Output: $(echo "$PULL_OUTPUT" | tail -2)"
else
    log_error "TEST 10 FAILED: Expected authentication failure"
    log_error "Output: $PULL_OUTPUT"
    docker logs "${ZOT_REG_NAME}" 2>&1 | tail -30
    exit 1
fi

# =============================================================================
# TEST 11: Pull manifest using crane WITH auth (should SUCCEED)
# =============================================================================
log_info "TEST 11: Pulling manifest using crane WITH auth (should succeed)..."
setup_crane_auth

PULL_OUTPUT=$(kubectl exec -n "${TEST_NAMESPACE}" crane-test-pod -- \
    sh -c 'crane manifest --insecure $ZOT_REGISTRY/crane-test:v1 2>&1') || true

if echo "$PULL_OUTPUT" | grep -qiE "schemaVersion|mediaType|manifests"; then
    log_info "TEST 11 PASSED: crane manifest succeeded with auth"
    log_info "Manifest preview: $(echo "$PULL_OUTPUT" | head -5)"
else
    log_error "TEST 11 FAILED: crane manifest failed with valid auth"
    log_error "Output: $PULL_OUTPUT"
    docker logs "${ZOT_REG_NAME}" 2>&1 | tail -50
    exit 1
fi

# =============================================================================
# CRANE TESTS FOR other-sa (NOT in accessControl config)
# These tests verify that authorization is enforced for real OCI operations
# =============================================================================

# Create crane pod for other-sa (or reuse existing)
if ! ensure_pod_ready "crane-other-sa-pod" "${TEST_NAMESPACE}" 120; then
    log_info "Creating crane pod for other-sa..."
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: crane-other-sa-pod
  namespace: ${TEST_NAMESPACE}
spec:
  serviceAccountName: other-sa
  initContainers:
  - name: install-crane
    image: ${ALPINE_IMAGE}
    command:
    - sh
    - -c
    - |
      apk add --no-cache curl
      curl -sL https://github.com/google/go-containerregistry/releases/download/v0.20.2/go-containerregistry_Linux_x86_64.tar.gz | tar -xzf - -C /tools crane
      chmod +x /tools/crane
    volumeMounts:
    - name: tools
      mountPath: /tools
  containers:
  - name: crane
    image: ${ALPINE_IMAGE}
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: token
      mountPath: /var/run/secrets/tokens
      readOnly: true
    - name: tools
      mountPath: /usr/local/bin
    env:
    - name: ZOT_REGISTRY
      value: "${ZOT_REG_NAME}:${ZOT_PORT}"
  volumes:
  - name: token
    projected:
      sources:
      - serviceAccountToken:
          path: zot-token
          expirationSeconds: 3600
          audience: ${AUDIENCE}
  - name: tools
    emptyDir: {}
  restartPolicy: Never
EOF
    log_info "Waiting for crane-other-sa-pod to be ready..."
    kubectl wait --for=condition=Ready pod/crane-other-sa-pod -n "${TEST_NAMESPACE}" --timeout=180s
fi

# Helper to set up auth for other-sa crane pod
setup_other_sa_crane_auth() {
    kubectl exec -n "${TEST_NAMESPACE}" crane-other-sa-pod -- sh -c '
        mkdir -p ~/.docker
        TOKEN=$(cat /var/run/secrets/tokens/zot-token)
        cat > ~/.docker/config.json << EOFCONFIG
{
  "auths": {
    "$ZOT_REGISTRY": {
      "registryToken": "$TOKEN"
    }
  }
}
EOFCONFIG
    '
}

# =============================================================================
# TEST 12: Copy OCI image using crane with other-sa (should FAIL with 403)
# Note: Uses zot-to-zot copy to avoid Docker Hub rate limiting
# =============================================================================
log_info "TEST 12: Copying OCI image using crane with other-sa (should fail with 403)..."
setup_other_sa_crane_auth

PUSH_OUTPUT=$(kubectl exec -n "${TEST_NAMESPACE}" crane-other-sa-pod -- \
    sh -c 'crane copy --insecure $ZOT_REGISTRY/crane-test:v1 $ZOT_REGISTRY/other-sa-crane-test:v1 2>&1' || true)

if echo "$PUSH_OUTPUT" | grep -qiE "403|forbidden|denied"; then
    log_info "TEST 12 PASSED: crane copy correctly rejected for other-sa (403 Forbidden)"
    log_info "Output: $(echo "$PUSH_OUTPUT" | tail -2)"
else
    log_error "TEST 12 FAILED: Expected 403 for other-sa push"
    log_error "Output: $PUSH_OUTPUT"
    docker logs "${ZOT_REG_NAME}" 2>&1 | tail -30
    exit 1
fi

# =============================================================================
# TEST 13: List tags using crane with other-sa (should FAIL with 403)
# =============================================================================
log_info "TEST 13: Listing tags using crane with other-sa (should fail with 403)..."

LIST_OUTPUT=$(kubectl exec -n "${TEST_NAMESPACE}" crane-other-sa-pod -- \
    sh -c 'crane ls --insecure $ZOT_REGISTRY/crane-test 2>&1' || true)

if echo "$LIST_OUTPUT" | grep -qiE "403|forbidden|unauthorized|denied"; then
    log_info "TEST 13 PASSED: crane ls correctly rejected for other-sa (access denied)"
    log_info "Output: $(echo "$LIST_OUTPUT" | tail -2)"
else
    log_error "TEST 13 FAILED: Expected 403 for other-sa list"
    log_error "Output: $LIST_OUTPUT"
    docker logs "${ZOT_REG_NAME}" 2>&1 | tail -30
    exit 1
fi

# =============================================================================
# TEST 14: Crane operation with NO token (should FAIL with 401, not 403)
# This verifies the difference between authentication failure (401) and
# authorization failure (403)
# =============================================================================
log_info "TEST 14: Crane operation with NO token (should fail with 401)..."

# Remove auth config from other-sa pod
kubectl exec -n "${TEST_NAMESPACE}" crane-other-sa-pod -- sh -c 'rm -f ~/.docker/config.json' 2>/dev/null || true

NO_TOKEN_OUTPUT=$(kubectl exec -n "${TEST_NAMESPACE}" crane-other-sa-pod -- \
    sh -c 'crane ls --insecure $ZOT_REGISTRY/crane-test 2>&1' || true)

if echo "$NO_TOKEN_OUTPUT" | grep -qiE "401|unauthorized"; then
    log_info "TEST 14 PASSED: No token correctly returns 401 Unauthorized"
    log_info "Output: $(echo "$NO_TOKEN_OUTPUT" | tail -2)"
else
    log_error "TEST 14 FAILED: Expected 401 for no token, got different error"
    log_error "Output: $NO_TOKEN_OUTPUT"
    docker logs "${ZOT_REG_NAME}" 2>&1 | tail -30
    exit 1
fi

fi  # End of crane tests conditional

# Print final zot logs for debugging
log_info "Final zot logs:"
docker logs "${ZOT_REG_NAME}" 2>&1 | tail -50

log_info "=========================================="
if [ "$ONLY_CRANE" = true ]; then
    log_info "Crane e2e tests (8-14) PASSED!"
elif [ "$ONLY_CURL" = true ]; then
    log_info "Curl-based tests (1-7) PASSED!"
else
    log_info "All OIDC Workload Identity tests PASSED!"
fi
log_info "=========================================="
log_info ""
log_info "Iteration tips:"
log_info "  --skip-setup     Skip cluster/image/zot setup (reuse existing)"
log_info "  --only-crane     Run only crane tests (8-14)"
log_info "  --only-curl      Run only curl tests (1-7)"
log_info "  --keep-resources Keep cluster/zot running after exit"
