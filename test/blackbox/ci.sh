#!/bin/bash

set -e

# Docker build env: single platform, no attestations (avoids OCI index / attestation manifest list)
export BUILDX_NO_DEFAULT_ATTESTATIONS=1
export DOCKER_DEFAULT_PLATFORM=linux/amd64

BATS_FLAGS=${BATS_FLAGS:-"--print-output-on-failure"}
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
BATS=${SCRIPTPATH}/../../hack/tools/bin/bats
PATH=$PATH:${SCRIPTPATH}/../../hack/tools/bin

# BLACKBOX_CI_SHARD selects a subset for parallel GitHub Actions jobs.
# Shards are CI-oriented (deps / theme), not zot build-tag "extensions":
#   registry  — dist-spec / auth / client push-pull style suites (+ systemd)
#   sync      — sync and related GC/scrub suites
#   host-deps — needs Docker helper images, npm OIDC provider, and/or stacker userns
#   upgrade   — release→new binary upgrade matrix (needs CRI-O)
# "all" is the ordered reunion of those shards.
shard_registry=("pushpull" "pushpull_authn" "pushpull_mount" "pushpull_mount_hydrate"
      "delete_images" "referrers" "sbom" "metadata" "anonymous_policy"
      "detect_manifest_collision" "cve" "metrics" "metrics_minimal"
      "multiarch_index" "docker_compat" "fips140" "fips140_authn"
      "dynamic_tls" "quota" "systemd")
shard_sync=("sync" "sync_docker" "sync_replica_cluster" "scrub" "garbage_collect")
shard_host_deps=("annotations" "redis_local" "redis_session_store"
      "events_nats" "events_http" "events_nats_lint_failure" "events_http_lint_failure"
      "events_sink_failure" "events_config_decoding" "openid_claim_mapping"
      "events_http_scan")
shard_upgrade=("upgrade" "upgrade_minimal")

case "${BLACKBOX_CI_SHARD:-all}" in
  upgrade)
    tests=("${shard_upgrade[@]}")
    ;;
  sync)
    tests=("${shard_sync[@]}")
    ;;
  registry)
    tests=("${shard_registry[@]}")
    ;;
  host-deps)
    tests=("${shard_host_deps[@]}")
    ;;
  all)
    tests=("${shard_registry[@]}" "${shard_sync[@]}" "${shard_host_deps[@]}" "${shard_upgrade[@]}")
    ;;
  *)
    echo "unknown BLACKBOX_CI_SHARD=${BLACKBOX_CI_SHARD}" >&2
    echo "expected one of: upgrade, sync, registry, host-deps, all" >&2
    exit 1
    ;;
esac

# Preload helper images after shard selection so each matrix job only pulls what it needs.
echo "Setting up Docker images for shard '${BLACKBOX_CI_SHARD:-all}'..."
${SCRIPTPATH}/setup_images.sh "${BLACKBOX_CI_SHARD:-all}"

echo "Running blackbox CI shard '${BLACKBOX_CI_SHARD:-all}': ${tests[*]}"

for test in ${tests[*]}; do
    ${BATS} ${BATS_FLAGS} ${SCRIPTPATH}/${test}.bats > ${test}.log & pids+=($!)
done

i=0
success="true"
for pid in ${pids[*]}; do
    if ! wait $pid; then
        echo "${tests[$i]} test returns an error !!!"
        cat ${tests[$i]}.log
        success="false"
        # we still need to wait for other PIDs to finish for the script to return properly
    else
        echo "${tests[$i]} test completed successfully."
    fi
    rm ${tests[$i]}.log
    i=$((i+1))
done

if [ "$success" == "false" ]; then
    exit 1
fi

echo "Successfully run all tests"
