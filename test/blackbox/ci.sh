#!/bin/bash

set -e

BATS_FLAGS=${BATS_FLAGS:-"--print-output-on-failure"}
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
BATS=${SCRIPTPATH}/../../hack/tools/bin/bats
PATH=$PATH:${SCRIPTPATH}/../../hack/tools/bin

# Pre-download Docker images before running tests
echo "Setting up Docker images..."
${SCRIPTPATH}/setup_images.sh

tests=("pushpull" "pushpull_authn" "delete_images" "referrers" "metadata" "anonymous_policy"
      "annotations" "detect_manifest_collision" "cve" "sync" "sync_docker" "sync_replica_cluster"
      "scrub" "garbage_collect" "metrics" "metrics_minimal" "multiarch_index" "docker_compat" "redis_local" "redis_session_store"
      "events_nats" "events_http" "events_nats_lint_failure" "events_http_lint_failure" "events_sink_failure" "events_config_decoding"
      "fips140" "fips140_authn" "openid_claim_mapping" "upgrade" "upgrade_minimal" "dynamic_tls")

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
