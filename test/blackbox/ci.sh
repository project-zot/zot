#!/bin/bash

set -e

BATS_FLAGS=${BATS_FLAGS:-"--print-output-on-failure"}
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
BATS=${SCRIPTPATH}/../../hack/tools/bin/bats
PATH=$PATH:${SCRIPTPATH}/../../hack/tools/bin

tests=("pushpull" "pushpull_authn" "delete_images" "referrers" "metadata" "anonymous_policy"
      "annotations" "detect_manifest_collision" "cve" "sync" "sync_docker" "sync_replica_cluster"
      "scrub" "garbage_collect" "metrics" "metrics_minimal" "multiarch_index" "redis_local")

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
