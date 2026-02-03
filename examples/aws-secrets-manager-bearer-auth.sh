#!/bin/bash
# AWS Secrets Manager Bearer Authentication E2E Test
#
# This script tests bearer authentication with JWT verification keys
# stored in AWS Secrets Manager. It uses hardcoded Ed25519 JWKS keys
# to sign JWTs and verifies that Zot correctly authenticates requests
# using keys retrieved from AWS Secrets Manager.
#
# The test:
# 1. Starts LocalStack (or uses real AWS) for Secrets Manager
# 2. Creates a secret with Ed25519 public keys
# 3. Builds and starts Zot with AWS Secrets Manager bearer auth
# 4. Tests push/pull operations with crane using pre-signed JWTs
# 5. Verifies authentication fails without a valid token
#
# By default, the script uses LocalStack (a local AWS emulator running in Docker)
# so no real AWS credentials are needed. Use --use-real-aws to test against
# a real AWS account with credentials from ~/.aws/credentials.
#
# Usage:
#   ./aws-secrets-manager-bearer-auth.sh [OPTIONS]
#
# Options:
#   --use-real-aws    Use real AWS Secrets Manager (requires ~/.aws/credentials)
#   --skip-build      Skip building zot (reuse existing binary)
#   --keep-resources  Don't clean up resources on exit
#   --region REGION   AWS region (default: us-east-1)
#   --help            Show this help message
#
# Prerequisites:
#   go, crane, jq, curl
#   For LocalStack mode (default): docker
#   For real AWS mode: aws CLI with configured credentials

set -o errexit
set -o pipefail

# Parse command line arguments
USE_REAL_AWS=false
SKIP_BUILD=false
KEEP_RESOURCES=false
AWS_REGION="us-east-1"

while [[ $# -gt 0 ]]; do
    case $1 in
        --use-real-aws)
            USE_REAL_AWS=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --keep-resources)
            KEEP_RESOURCES=true
            shift
            ;;
        --region)
            AWS_REGION="$2"
            shift 2
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

# Check prerequisites
check_prerequisites() {
    local missing=""
    for cmd in go crane jq curl; do
        if ! command -v "$cmd" &> /dev/null; then
            missing="$missing $cmd"
        fi
    done

    if [ "$USE_REAL_AWS" = true ]; then
        if ! command -v aws &> /dev/null; then
            missing="$missing aws"
        fi
    else
        if ! command -v docker &> /dev/null; then
            missing="$missing docker"
        fi
        # Also need aws CLI to talk to LocalStack
        if ! command -v aws &> /dev/null; then
            missing="$missing aws"
        fi
    fi

    if [ -n "$missing" ]; then
        log_error "Missing required tools:$missing"
        exit 1
    fi

    if [ "$USE_REAL_AWS" = true ]; then
        # Verify AWS credentials are configured
        if ! aws sts get-caller-identity --region "${AWS_REGION}" &>/dev/null; then
            log_error "AWS credentials not configured or invalid. Check ~/.aws/credentials"
            exit 1
        fi
        log_info "AWS credentials verified (real AWS mode)"
    else
        log_info "Using LocalStack mode (no real AWS credentials needed)"
    fi
}

check_prerequisites

ROOT_DIR=$(git rev-parse --show-toplevel)
cd "${ROOT_DIR}"

# Configuration
ZOT_PORT="5000"
ZOT_BINARY="/tmp/zot-asm-test"
ZOT_CONFIG="/tmp/zot-asm-config.json"
ZOT_STORAGE="/tmp/zot-asm-storage"
ZOT_PID_FILE="/tmp/zot-asm-test.pid"
SECRET_NAME="zot/e2e-test-jwt-keys-$(date +%s)"
LOCALSTACK_CONTAINER="localstack-zot-asm-test"
LOCALSTACK_PORT="4566"
BUSYBOX_IMAGE="gcr.io/google-containers/busybox:1.27"

# AWS CLI flags: when using LocalStack, point the AWS CLI at the local endpoint
# and set dummy credentials (LocalStack doesn't validate them).
if [ "$USE_REAL_AWS" = true ]; then
    AWS_CMD_FLAGS="--region ${AWS_REGION}"
else
    AWS_CMD_FLAGS="--region ${AWS_REGION} --endpoint-url http://127.0.0.1:${LOCALSTACK_PORT}"
    export AWS_ACCESS_KEY_ID="test"
    export AWS_SECRET_ACCESS_KEY="test"
fi

# Ed25519 public JWKS key stored in AWS Secrets Manager for JWT verification.
PUBLIC_JWKS='{"keys":[{"use":"sig","kty":"OKP","kid":"01f0ff96-0286-62c9-9fe0-68c6ac4f48e0","crv":"Ed25519","alg":"EdDSA","x":"3pL95mHbZYNG6-YT_MqXKibGQrXF7WziWk25EcgEJGs"}]}'
KID="01f0ff96-0286-62c9-9fe0-68c6ac4f48e0"

# Pre-signed long-lived JWTs (exp ~2126) for test use only. Signed with the Ed25519
# private key corresponding to the public key above (private key not stored in repo).
# JWT with push+pull access to "test-repo"
TOKEN_PUSH_PULL="eyJhbGciOiJFZERTQSIsImtpZCI6IjAxZjBmZjk2LTAyODYtNjJjOS05ZmUwLTY4YzZhYzRmNDhlMCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzZXJ2aWNlLWFjY291bnQtMSIsImV4cCI6NDkyMzY0NzIxMCwiaWF0IjoxNzcwMDQ3MjEwLCJhY2Nlc3MiOlt7InR5cGUiOiJyZXBvc2l0b3J5IiwibmFtZSI6InRlc3QtcmVwbyIsImFjdGlvbnMiOlsicHVsbCIsInB1c2giXX1dfQ.D8CN1Yt5gUV9ZEJHOkJWmEa54Ame5oHyERjH0-_TDkLBa2hjHRq6StJOUCl8wejZ2O_oFGspdlz2X_MVwWXMCQ"
# JWT with pull-only access to "test-repo"
TOKEN_PULL_ONLY="eyJhbGciOiJFZERTQSIsImtpZCI6IjAxZjBmZjk2LTAyODYtNjJjOS05ZmUwLTY4YzZhYzRmNDhlMCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzZXJ2aWNlLWFjY291bnQtMSIsImV4cCI6NDkyMzY0NzIxMiwiaWF0IjoxNzcwMDQ3MjEyLCJhY2Nlc3MiOlt7InR5cGUiOiJyZXBvc2l0b3J5IiwibmFtZSI6InRlc3QtcmVwbyIsImFjdGlvbnMiOlsicHVsbCJdfV19.QqVzME9mO61QBhw1gQhBFleBv76Aju3hUVxv-KWZdyYKwHiXINX6vMW8aKWG81DMam26Y19GeMK7QRz5Sg6rAw"
# JWT with no access claims (authentication only)
TOKEN_NO_ACCESS="eyJhbGciOiJFZERTQSIsImtpZCI6IjAxZjBmZjk2LTAyODYtNjJjOS05ZmUwLTY4YzZhYzRmNDhlMCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzZXJ2aWNlLWFjY291bnQtMSIsImV4cCI6NDkyMzY0NzIxMiwiaWF0IjoxNzcwMDQ3MjEyfQ.t-1eng92zu7W4tfskVMHkynlvojSEnwHlWOCIc2MN234rMeqyPZrD9tFmkKsEWlznJpKIo-wMXY70JQkOCQ8Bg"
# JWT with wrong kid (for rejection test)
TOKEN_WRONG_KID="eyJhbGciOiJFZERTQSIsImtpZCI6Indyb25nLWtpZC1kb2VzLW5vdC1leGlzdCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzZXJ2aWNlLWFjY291bnQtMSIsImV4cCI6NDkyMzY0NzIxMiwiaWF0IjoxNzcwMDQ3MjEyLCJhY2Nlc3MiOlt7InR5cGUiOiJyZXBvc2l0b3J5IiwibmFtZSI6InRlc3QtcmVwbyIsImFjdGlvbnMiOlsicHVsbCJdfV19.4WKgZIQwAxTG3xJsn83_qpq1w_b1WvQR977Hj-1LlTKred8bfrcbJt9Fy7_gzP5ee6UgFs-IitldL6hy6emYAA"

cleanup() {
    if [ "$KEEP_RESOURCES" = true ]; then
        log_info "Keeping resources (--keep-resources specified)"
        log_info "To clean up manually:"
        if [ "$USE_REAL_AWS" = true ]; then
            log_info "  aws secretsmanager delete-secret --secret-id '${SECRET_NAME}' --force-delete-without-recovery --region '${AWS_REGION}'"
        else
            log_info "  docker rm -f ${LOCALSTACK_CONTAINER}"
        fi
        log_info "  kill \$(cat ${ZOT_PID_FILE}) 2>/dev/null"
        log_info "  rm -rf ${ZOT_STORAGE} ${ZOT_CONFIG}"
        return
    fi

    log_info "Cleaning up..."

    # Stop zot
    if [ -f "${ZOT_PID_FILE}" ]; then
        kill "$(cat "${ZOT_PID_FILE}")" 2>/dev/null || true
        rm -f "${ZOT_PID_FILE}"
    fi

    if [ "$USE_REAL_AWS" = true ]; then
        # Delete the secret from AWS Secrets Manager
        aws secretsmanager delete-secret \
            --secret-id "${SECRET_NAME}" \
            --force-delete-without-recovery \
            --region "${AWS_REGION}" 2>/dev/null || true
    else
        # Stop LocalStack
        docker rm -f "${LOCALSTACK_CONTAINER}" 2>/dev/null || true
    fi

    # Clean up local files
    rm -rf "${ZOT_STORAGE}" "${ZOT_CONFIG}" /tmp/zot-asm-docker 2>/dev/null || true
}

trap cleanup EXIT

# =============================================================================
# SETUP
# =============================================================================

# Step 1: Start LocalStack if not using real AWS
if [ "$USE_REAL_AWS" = false ]; then
    log_info "Starting LocalStack..."
    docker rm -f "${LOCALSTACK_CONTAINER}" 2>/dev/null || true
    docker run -d \
        --name "${LOCALSTACK_CONTAINER}" \
        -p "${LOCALSTACK_PORT}:4566" \
        ghcr.io/project-zot/ci-images/localstack:3.3.0

    # Wait for LocalStack to be ready
    log_info "Waiting for LocalStack to be ready..."
    for i in {1..30}; do
        if curl -s "http://127.0.0.1:${LOCALSTACK_PORT}/_localstack/health" 2>/dev/null | grep -q '"secretsmanager"'; then
            log_info "LocalStack is ready"
            break
        fi
        if [ "$i" -eq 30 ]; then
            log_error "LocalStack failed to start"
            docker logs "${LOCALSTACK_CONTAINER}" 2>&1 | tail -20
            exit 1
        fi
        sleep 1
    done
fi

# Step 2: Create the secret in AWS Secrets Manager
log_info "Creating secret '${SECRET_NAME}' in Secrets Manager (${AWS_REGION})..."

# The secret format is a JSON object: {"kid": "JWKS-or-PEM-string"}
# We store the public key in JWKS format.
SECRET_VALUE=$(jq -n --arg kid "$KID" --arg key "$PUBLIC_JWKS" '{($kid): $key}')

# shellcheck disable=SC2086
aws secretsmanager create-secret \
    --name "${SECRET_NAME}" \
    --secret-string "${SECRET_VALUE}" \
    ${AWS_CMD_FLAGS} \
    --output json | jq .

log_info "Secret created successfully"

# Verify the secret can be retrieved
log_info "Verifying secret retrieval..."
# shellcheck disable=SC2086
RETRIEVED=$(aws secretsmanager get-secret-value \
    --secret-id "${SECRET_NAME}" \
    ${AWS_CMD_FLAGS} \
    --query 'SecretString' \
    --output text)

if [ "$(echo "$RETRIEVED" | jq -r ".[\"$KID\"]")" = "$PUBLIC_JWKS" ]; then
    log_info "Secret verification passed"
else
    log_error "Secret verification failed"
    log_error "Expected: $PUBLIC_JWKS"
    log_error "Got: $(echo "$RETRIEVED" | jq -r ".[\"$KID\"]")"
    exit 1
fi

# Step 3: Build zot
if [ "$SKIP_BUILD" = true ] && [ -f "${ZOT_BINARY}" ]; then
    log_info "Skipping build (--skip-build specified, using existing binary)"
else
    log_info "Building zot..."
    go build -o "${ZOT_BINARY}" ./cmd/zot
    log_info "Zot built: ${ZOT_BINARY}"
fi

# Step 4: Create zot configuration
log_info "Creating zot configuration..."
rm -rf "${ZOT_STORAGE}"
mkdir -p "${ZOT_STORAGE}"

cat > "${ZOT_CONFIG}" <<EOF
{
  "distSpecVersion": "1.1.1",
  "storage": {
    "rootDirectory": "${ZOT_STORAGE}"
  },
  "http": {
    "address": "127.0.0.1",
    "port": "${ZOT_PORT}",
    "compat": ["docker2s2"],
    "auth": {
      "bearer": {
        "realm": "zot",
        "service": "zot-service",
        "awsSecretsManager": {
          "region": "${AWS_REGION}",
          "secretName": "${SECRET_NAME}",
          "refreshInterval": "30s"
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
jq . "${ZOT_CONFIG}"

# Step 5: Start zot
# When using LocalStack, set AWS_ENDPOINT_URL so the AWS SDK in zot talks to LocalStack.
# Also set dummy credentials for LocalStack (it doesn't validate them).
log_info "Starting zot..."
if [ "$USE_REAL_AWS" = true ]; then
    "${ZOT_BINARY}" serve "${ZOT_CONFIG}" &
else
    AWS_ENDPOINT_URL="http://127.0.0.1:${LOCALSTACK_PORT}" \
    AWS_ACCESS_KEY_ID="test" \
    AWS_SECRET_ACCESS_KEY="test" \
    "${ZOT_BINARY}" serve "${ZOT_CONFIG}" &
fi
ZOT_PID=$!
echo "${ZOT_PID}" > "${ZOT_PID_FILE}"
log_info "Zot started with PID ${ZOT_PID}"

# Wait for zot to be ready
log_info "Waiting for zot to be ready..."
for i in {1..30}; do
    HTTP_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${ZOT_PORT}/v2/" 2>/dev/null || echo "000")
    if [ "$HTTP_RESPONSE" = "401" ] || [ "$HTTP_RESPONSE" = "200" ]; then
        log_info "Zot is responding (HTTP $HTTP_RESPONSE)"
        break
    fi
    if [ "$i" -eq 30 ]; then
        log_error "Zot failed to start (last HTTP response: $HTTP_RESPONSE)"
        exit 1
    fi
    sleep 1
done

# Helper: configure crane docker config with a given token
setup_crane_docker_config() {
    local token="$1"
    mkdir -p /tmp/zot-asm-docker
    cat > /tmp/zot-asm-docker/config.json <<EOFCONFIG
{
  "auths": {
    "127.0.0.1:${ZOT_PORT}": {
      "registryToken": "${token}"
    }
  }
}
EOFCONFIG
}

remove_crane_auth() {
    rm -f /tmp/zot-asm-docker/config.json
}

REGISTRY="127.0.0.1:${ZOT_PORT}"

# =============================================================================
# TESTS
# =============================================================================

# TEST 1: Basic authentication check (GET /v2/ with valid token)
log_info "TEST 1: Verifying basic authentication with valid token..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${TOKEN_NO_ACCESS}" \
    "http://${REGISTRY}/v2/")

if [ "$HTTP_CODE" = "200" ]; then
    log_info "TEST 1 PASSED: Authentication succeeded (HTTP $HTTP_CODE)"
else
    log_error "TEST 1 FAILED: Expected 200, got HTTP $HTTP_CODE"
    exit 1
fi

# TEST 2: Authentication fails without token
log_info "TEST 2: Verifying authentication fails without token..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://${REGISTRY}/v2/")

if [ "$HTTP_CODE" = "401" ]; then
    log_info "TEST 2 PASSED: No token correctly rejected (HTTP $HTTP_CODE)"
else
    log_error "TEST 2 FAILED: Expected 401, got HTTP $HTTP_CODE"
    exit 1
fi

# TEST 3: Authentication fails with invalid token
log_info "TEST 3: Verifying authentication fails with invalid token..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer invalid.token.here" \
    "http://${REGISTRY}/v2/")

if [ "$HTTP_CODE" = "401" ]; then
    log_info "TEST 3 PASSED: Invalid token correctly rejected (HTTP $HTTP_CODE)"
else
    log_error "TEST 3 FAILED: Expected 401, got HTTP $HTTP_CODE"
    exit 1
fi

# TEST 4: Push OCI image using crane WITH push+pull token
log_info "TEST 4: Pushing OCI image using crane with push+pull token..."
setup_crane_docker_config "$TOKEN_PUSH_PULL"

PUSH_OUTPUT=$(DOCKER_CONFIG=/tmp/zot-asm-docker crane copy --insecure --platform linux/amd64 \
    "${BUSYBOX_IMAGE}" "${REGISTRY}/test-repo:v1" 2>&1) || true

if echo "$PUSH_OUTPUT" | grep -qiE "error|UNAUTHORIZED|unauthorized|401|403"; then
    log_error "TEST 4 FAILED: crane copy failed"
    log_error "Output: $PUSH_OUTPUT"
    exit 1
else
    log_info "TEST 4 PASSED: crane copy succeeded with push+pull token"
    log_info "Output: $(echo "$PUSH_OUTPUT" | tail -3)"
fi

# TEST 5: List tags using crane WITH pull token
log_info "TEST 5: Listing tags using crane with pull-only token..."
setup_crane_docker_config "$TOKEN_PULL_ONLY"

TAGS_OUTPUT=$(DOCKER_CONFIG=/tmp/zot-asm-docker crane ls --insecure \
    "${REGISTRY}/test-repo" 2>&1) || true

if echo "$TAGS_OUTPUT" | grep -q "v1"; then
    log_info "TEST 5 PASSED: crane ls succeeded and found tag 'v1'"
    log_info "Tags: $TAGS_OUTPUT"
else
    log_error "TEST 5 FAILED: Expected to find tag 'v1'"
    log_error "Output: $TAGS_OUTPUT"
    exit 1
fi

# TEST 6: Pull manifest using crane WITH pull token
log_info "TEST 6: Pulling manifest using crane with pull-only token..."
setup_crane_docker_config "$TOKEN_PULL_ONLY"

MANIFEST_OUTPUT=$(DOCKER_CONFIG=/tmp/zot-asm-docker crane manifest --insecure \
    "${REGISTRY}/test-repo:v1" 2>&1) || true

if echo "$MANIFEST_OUTPUT" | grep -qiE "schemaVersion|mediaType|manifests"; then
    log_info "TEST 6 PASSED: crane manifest succeeded with pull token"
    log_info "Manifest preview: $(echo "$MANIFEST_OUTPUT" | head -5)"
else
    log_error "TEST 6 FAILED: crane manifest failed with valid pull token"
    log_error "Output: $MANIFEST_OUTPUT"
    exit 1
fi

# TEST 7: Push fails with pull-only token
log_info "TEST 7: Verifying push fails with pull-only token..."
setup_crane_docker_config "$TOKEN_PULL_ONLY"

PUSH_FAIL_OUTPUT=$(DOCKER_CONFIG=/tmp/zot-asm-docker crane copy --insecure --platform linux/amd64 \
    "${BUSYBOX_IMAGE}" "${REGISTRY}/test-repo:v2" 2>&1 || true)

if echo "$PUSH_FAIL_OUTPUT" | grep -qiE "401|unauthorized|UNAUTHORIZED"; then
    log_info "TEST 7 PASSED: Push correctly rejected with pull-only token"
    log_info "Output: $(echo "$PUSH_FAIL_OUTPUT" | tail -2)"
else
    log_error "TEST 7 FAILED: Expected 401 for push with pull-only token"
    log_error "Output: $PUSH_FAIL_OUTPUT"
    exit 1
fi

# TEST 8: crane operations fail WITHOUT any token
log_info "TEST 8: Verifying crane operations fail without token..."
remove_crane_auth

NOTOK_OUTPUT=$(DOCKER_CONFIG=/tmp/zot-asm-docker crane ls --insecure \
    "${REGISTRY}/test-repo" 2>&1 || true)

if echo "$NOTOK_OUTPUT" | grep -qiE "401|unauthorized|UNAUTHORIZED|error|Error"; then
    log_info "TEST 8 PASSED: crane ls failed without token"
    log_info "Output: $(echo "$NOTOK_OUTPUT" | tail -2)"
else
    log_error "TEST 8 FAILED: Expected error for unauthenticated request"
    log_error "Output: $NOTOK_OUTPUT"
    exit 1
fi

# TEST 9: Token with wrong kid is rejected
log_info "TEST 9: Verifying token with wrong kid is rejected..."

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${TOKEN_WRONG_KID}" \
    "http://${REGISTRY}/v2/")

if [ "$HTTP_CODE" = "401" ]; then
    log_info "TEST 9 PASSED: Wrong kid correctly rejected (HTTP $HTTP_CODE)"
else
    log_error "TEST 9 FAILED: Expected 401 for wrong kid, got HTTP $HTTP_CODE"
    exit 1
fi

# TEST 10: Token accessing unauthorized repository is rejected
log_info "TEST 10: Verifying access to unauthorized repository fails..."

# The push+pull token only grants access to "test-repo"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${TOKEN_PUSH_PULL}" \
    "http://${REGISTRY}/v2/other-repo/tags/list")

if [ "$HTTP_CODE" = "401" ]; then
    log_info "TEST 10 PASSED: Access to unauthorized repo correctly rejected (HTTP $HTTP_CODE)"
else
    log_error "TEST 10 FAILED: Expected 401 for unauthorized repo, got HTTP $HTTP_CODE"
    exit 1
fi

# =============================================================================
# SUMMARY
# =============================================================================

log_info "=========================================="
log_info "All AWS Secrets Manager Bearer Auth tests PASSED!"
log_info "=========================================="
log_info ""
log_info "Options:"
log_info "  --use-real-aws    Use real AWS (default: LocalStack)"
log_info "  --skip-build      Skip building zot"
log_info "  --keep-resources  Keep resources after exit"
log_info "  --region REGION   AWS region (default: us-east-1)"
