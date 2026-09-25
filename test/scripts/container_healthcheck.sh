#!/usr/bin/env bash
# Smoke-test a zot image with docker or podman.
#
# Usage:
#   test/scripts/container_healthcheck.sh --runtime <docker|podman> --image <ref> \
#     [--health-bin <path>]
#
# Without --health-bin, the image HEALTHCHECK is used and /usr/bin/zot is exec'd.
# With --health-bin, podman gets exec-form --health-cmd; docker only execs.

set -euo pipefail

RUNTIME=""
IMAGE=""
HEALTH_BIN="/usr/bin/zot"
USE_IMAGE_HEALTHCHECK=1

usage() {
  echo "usage: $0 --runtime <docker|podman> --image <ref> [--health-bin <path>]" >&2
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

[ -n "${RUNTIME}" ] && [ -n "${IMAGE}" ] || usage

NAME="zot-hc-$$"
PORT="${ZOT_TEST_PORT:-5000}"

cleanup() {
  "${RUNTIME}" rm -f "${NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
  echo "$*" >&2
  "${RUNTIME}" logs "${NAME}" >&2 || true
  "${RUNTIME}" inspect "${NAME}" >&2 || true
  exit 1
}

# --- start -------------------------------------------------------------------
# `run -d` only starts the container; it does not wait for healthy.
# --health-* flags (below) tell the engine how to probe in the background and
# update .State.Health.Status. This script checks that status later via inspect.
run_args=(-d --name "${NAME}" -p "${PORT}:5000")
# runtime_health=1 when the runtime should manage HEALTHCHECK (image-baked or
# podman --health-cmd). When 0 (docker + --health-bin), we only exec the probe.
runtime_health=0

if [ "${USE_IMAGE_HEALTHCHECK}" -eq 1 ]; then
  runtime_health=1
elif [ "${RUNTIME}" = "podman" ]; then
  runtime_health=1
  run_args+=(--health-cmd="[\"${HEALTH_BIN}\",\"healthcheck\",\"--insecure-skip-verify\",\"/etc/zot/config.json\"]")
fi

if [ "${runtime_health}" -eq 1 ]; then
  # Scheduling knobs for the engine's background HEALTHCHECK.
  run_args+=(
    --health-interval=2s
    --health-timeout=5s
    --health-retries=10
    --health-start-period=2s
  )
fi

# Returns as soon as the container is created; health flags do not block until healthy.
"${RUNTIME}" run "${run_args[@]}" "${IMAGE}"

# --- ready -------------------------------------------------------------------
# Wait until zot serves the registry API (independent of HEALTHCHECK status).
ready=0
for _ in $(seq 1 60); do
  if curl --silent --show-error --fail --connect-timeout 2 --max-time 5 \
    "http://localhost:${PORT}/v2/" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
[ "${ready}" -eq 1 ] || fail "timed out waiting for http://localhost:${PORT}/v2/"

# --- probe -------------------------------------------------------------------
# Directly run the healthcheck subcommand inside the container.
"${RUNTIME}" exec "${NAME}" "${HEALTH_BIN}" healthcheck --insecure-skip-verify /etc/zot/config.json \
  || fail "exec healthcheck failed"
echo "${RUNTIME} exec healthcheck ok"

# --- runtime health ----------------------------------------------------------
# Poll the status the engine maintains from its background HEALTHCHECK probes.
[ "${runtime_health}" -eq 1 ] || exit 0

status="none"
for _ in $(seq 1 60); do
  status="$("${RUNTIME}" inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${NAME}")"
  case "${status}" in
    healthy)
      echo "${RUNTIME} container ${NAME} is healthy"
      # Optionally force one probe now (podman); docker has no equivalent.
      if [ "${RUNTIME}" = "podman" ]; then
        "${RUNTIME}" healthcheck run "${NAME}" || fail "${RUNTIME} healthcheck run failed"
      fi
      exit 0
      ;;
    unhealthy)
      fail "container became unhealthy"
      ;;
  esac
  sleep 1
done
fail "timed out waiting for healthy status (last=${status})"
