#!/usr/bin/env bash
# Exercise one zot image with docker or podman.
#
# Starts the image on its own HTTP config, runs the healthcheck, and copies
# the payload in and out. Then starts it again with a mounted TLS config,
# curls /v2/, and copies the payload again. A failed HTTP phase still runs
# HTTPS. The container is removed between the two phases.
#
# The image has no shell, so the cert, key, and config are bind-mounted.
# Files are mode 0644 and the directory is mode 0755 so uid 65532 can read them.
#
# Usage:
#   test/scripts/container_check.sh --runtime <docker|podman> --image <ref> \
#     --payload <ref> [--health-bin <path>]
#
# Without --health-bin, the image HEALTHCHECK is used and /usr/bin/zot is exec'd.
# With --health-bin, podman gets exec-form --health-cmd; docker only execs.
# The HTTPS process mounts its config at /etc/zot/config.json, the path the image HEALTHCHECK reads.

set -euo pipefail

RUNTIME=""
IMAGE=""
PAYLOAD=""
HEALTH_BIN="/usr/bin/zot"
USE_IMAGE_HEALTHCHECK=1

usage() {
  echo "usage: $0 --runtime <docker|podman> --image <ref> --payload <ref> [--health-bin <path>]" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --runtime)
      [ $# -ge 2 ] || usage
      RUNTIME="$2"
      shift 2
      ;;
    --image)
      [ $# -ge 2 ] || usage
      IMAGE="$2"
      shift 2
      ;;
    --payload)
      [ $# -ge 2 ] || usage
      PAYLOAD="$2"
      shift 2
      ;;
    --health-bin)
      [ $# -ge 2 ] || usage
      HEALTH_BIN="$2"
      USE_IMAGE_HEALTHCHECK=0
      shift 2
      ;;
    -h | --help)
      usage
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      ;;
  esac
done

[ -n "${RUNTIME}" ] && [ -n "${IMAGE}" ] && [ -n "${PAYLOAD}" ] || usage

NAME="zot-check-$$"
PORT="${ZOT_TEST_PORT:-5000}"
WORKDIR="$(mktemp -d)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cleanup() {
  "${RUNTIME}" rm -f "${NAME}" >/dev/null 2>&1 || true
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

log() {
  echo "container_check: ${RUNTIME} ${IMAGE}: $*"
}

fail() {
  echo "container_check: ${RUNTIME} ${IMAGE}: $*" >&2
  "${RUNTIME}" logs "${NAME}" >&2 || true
  "${RUNTIME}" inspect "${NAME}" >&2 || true
  exit 1
}

wait_ready() {
  local url="$1"
  shift
  local ready=0
  local _
  for _ in $(seq 1 60); do
    if curl --silent --show-error --fail --connect-timeout 2 --max-time 5 \
      "$@" "${url}" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  [ "${ready}" -eq 1 ] || fail "timed out waiting for ${url}"
}

# tls-verify=false makes skopeo use HTTP, and it skips certificate checks for HTTPS.
# --format oci keeps the manifest acceptable to zot-minimal, which has no docker2s2 compat.
round_trip() {
  local scheme="$1"
  local pulldir="${WORKDIR}/pulled-${scheme}"
  local registry="localhost:${PORT}/payload:ci"
  local pushed=""
  local pulled=""
  mkdir -p "${pulldir}"
  log "${scheme}: pushing ${PAYLOAD} to ${registry}"
  skopeo copy --dest-tls-verify=false --format oci \
    "docker-daemon:${PAYLOAD}" "docker://${registry}" \
    || fail "${scheme} push to ${registry} failed"
  log "${scheme}: pulling ${registry}"
  skopeo copy --src-tls-verify=false \
    "docker://${registry}" "dir:${pulldir}" \
    || fail "${scheme} pull from ${registry} failed"
  pushed="$(skopeo inspect --tls-verify=false --format '{{.Digest}}' "docker://${registry}")"
  pulled="$(skopeo inspect --format '{{.Digest}}' "dir:${pulldir}")"
  [ -n "${pushed}" ] && [ "${pushed}" = "${pulled}" ] \
    || fail "${scheme} digest mismatch pushed=${pushed} pulled=${pulled}"
  log "${scheme}: push/pull ok (${pushed})"
}

run_http() {
  # `run -d` only starts the container; it does not wait for healthy.
  # --health-* flags tell the engine how to probe in the background and
  # update .State.Health.Status. This script checks that status later via inspect.
  local run_args=(-d --name "${NAME}" -p "${PORT}:5000")
  # runtime_health=1 when the runtime should manage HEALTHCHECK (image-baked or
  # podman --health-cmd). When 0 (docker + --health-bin), we only exec the probe.
  local runtime_health=0
  local status="none"
  local became_healthy=0
  local _

  if [ "${USE_IMAGE_HEALTHCHECK}" -eq 1 ]; then
    runtime_health=1
  elif [ "${RUNTIME}" = "podman" ]; then
    runtime_health=1
    run_args+=(--health-cmd="[\"${HEALTH_BIN}\",\"healthcheck\",\"--insecure-skip-verify\",\"/etc/zot/config.json\"]")
  fi

  if [ "${runtime_health}" -eq 1 ]; then
    run_args+=(
      --health-interval=2s
      --health-timeout=5s
      --health-retries=10
      --health-start-period=2s
    )
  fi

  # Returns as soon as the container is created; health flags do not block until healthy.
  log "http: starting ${NAME} on port ${PORT} with the image config"
  cid="$("${RUNTIME}" run "${run_args[@]}" "${IMAGE}")"
  log "http: started ${cid}"

  # Wait until zot serves the registry API (independent of HEALTHCHECK status).
  log "http: waiting for http://localhost:${PORT}/v2/"
  wait_ready "http://localhost:${PORT}/v2/"

  # Directly run the healthcheck subcommand inside the container.
  log "http: exec ${HEALTH_BIN} healthcheck"
  "${RUNTIME}" exec "${NAME}" "${HEALTH_BIN}" healthcheck --insecure-skip-verify /etc/zot/config.json \
    || fail "exec healthcheck failed"
  log "http: exec healthcheck ok"

  # Poll the status the engine maintains from its background HEALTHCHECK probes.
  # docker with --health-bin cannot set a health command, so only the exec above runs.
  if [ "${runtime_health}" -eq 0 ]; then
    log "http: engine health status is not used for this runtime"
  else
    log "http: waiting for the engine health status"
    for _ in $(seq 1 60); do
      status="$("${RUNTIME}" inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${NAME}")"
      case "${status}" in
        healthy)
          log "http: engine reports healthy"
          # Optionally force one probe now (podman); docker has no equivalent.
          if [ "${RUNTIME}" = "podman" ]; then
            "${RUNTIME}" healthcheck run "${NAME}" || fail "${RUNTIME} healthcheck run failed"
          fi
          became_healthy=1
          break
          ;;
        unhealthy)
          fail "container became unhealthy"
          ;;
      esac
      sleep 1
    done
    [ "${became_healthy}" -eq 1 ] || fail "timed out waiting for healthy status (last=${status})"
  fi

  round_trip http
}

run_https() {
  mkdir -p "${WORKDIR}/tls"
  log "https: generating certificates"
  if ! (
    cd "${WORKDIR}/tls"
    bash "${SCRIPT_DIR}/gen_certs.sh"
  ) >"${WORKDIR}/gen_certs.log" 2>&1; then
    cat "${WORKDIR}/gen_certs.log" >&2 || true
    fail "https: certificate generation failed"
  fi
  chmod 755 "${WORKDIR}/tls"
  chmod 644 "${WORKDIR}/tls/server.cert" "${WORKDIR}/tls/server.key"
  cat > "${WORKDIR}/tls/config.json" <<'EOF'
{
  "storage": {
    "rootDirectory": "/var/lib/registry"
  },
  "http": {
    "address": "0.0.0.0",
    "port": "5000",
    "tls": {
      "cert": "/etc/zot/server.cert",
      "key": "/etc/zot/server.key"
    }
  },
  "log": {
    "level": "debug"
  }
}
EOF
  chmod 644 "${WORKDIR}/tls/config.json"

  # Mount over /etc/zot so serve and the image HEALTHCHECK read this TLS config.
  log "https: starting ${NAME} on port ${PORT} with the mounted TLS config"
  cid="$("${RUNTIME}" run -d --name "${NAME}" -p "${PORT}:5000" \
    -v "${WORKDIR}/tls:/etc/zot:ro" \
    "${IMAGE}" serve /etc/zot/config.json)"
  log "https: started ${cid}"

  log "https: waiting for https://localhost:${PORT}/v2/"
  wait_ready "https://localhost:${PORT}/v2/" --insecure
  log "https: registry is serving"
  round_trip https
}

# A subshell keeps set -e local to the phase. The parent records the status
# and still runs the other phase.
failed=0
log "port ${PORT}, payload ${PAYLOAD}"

set +e
(
  set -euo pipefail
  run_http
)
http_status=$?
set -e
"${RUNTIME}" rm -f "${NAME}" >/dev/null 2>&1 || true
if [ "${http_status}" -ne 0 ]; then
  log "http phase failed, continuing with https"
  failed=1
fi

set +e
(
  set -euo pipefail
  run_https
)
https_status=$?
set -e
if [ "${https_status}" -ne 0 ]; then
  log "https phase failed"
  failed=1
fi

if [ "${failed}" -eq 0 ]; then
  log "ok"
else
  log "failed"
fi

exit "${failed}"
