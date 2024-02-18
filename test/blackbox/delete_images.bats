# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot

function verify_prerequisites {
    if [ ! command -v curl ] &>/dev/null; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! command -v jq ] &>/dev/null; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi
}

function setup_file() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/test-images/alpine:3.17.3 oci:${TEST_DATA_DIR}/alpine:3.17.3

    # Setup zot server
    ZOT_ROOT_DIR=${BATS_FILE_TMPDIR}/zot
    echo ${ZOT_ROOT_DIR}
    local zot_log_file=${BATS_FILE_TMPDIR}/zot-log.json
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    mkdir -p ${ZOT_ROOT_DIR}
    touch ${zot_log_file}
    zot_port=$(get_free_port)
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    cat >${zot_config_file} <<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${ZOT_ROOT_DIR}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}"
    },
    "log": {
        "level": "debug",
        "output": "${zot_log_file}"
    },
    "extensions": {
        "search": {
            "enable": true
        }
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}

    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/alpine:3.17.3 \
        docker://127.0.0.1:${zot_port}/alpine:3.17.3
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"alpine"' ]

    MANIFEST_DIGEST=$(skopeo inspect --tls-verify=false docker://localhost:${zot_port}/alpine:3.17.3 | jq -r '.Digest')
    echo ${MANIFEST_DIGEST}
}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot-log.json
}

function teardown_file() {
    zot_stop_all
}

@test "delete one manifest by it's tag" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"alpine"' ]

    run curl -i -X GET  http://localhost:${zot_port}/v2/alpine/manifests/3.17.3
    [ "$status" -eq 0 ]
    echo $(echo "${lines[-1]}")

    foundConfigDigest=0
    for i in "${lines[@]}"
    do
        if [[ "$i" == *"\"digest\":\"sha256:4798f93a2cc876a25ef1f5ae73e7a2ff7132ddc2746fc22632a2641b318eb56c\""* ]]; then
            foundConfigDigest=1
        fi
    done
    [ "$foundConfigDigest" -eq 1 ]

    run curl -X DELETE  http://localhost:${zot_port}/v2/alpine/manifests/3.17.3
    [ "$status" -eq 0 ]

    run curl -i -X GET  http://localhost:${zot_port}/v2/alpine/manifests/3.17.3
    [ "$status" -eq 0 ]
    
    found=0
    for i in "${lines[@]}"
    do
        if [[ "$i" = *"MANIFEST_UNKNOWN"* ]]; then
            found=1
        fi
    done
    [ "$found" -eq 1 ]
}
