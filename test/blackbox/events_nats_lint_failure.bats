# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_events

function verify_prerequisites() {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v jq) ]; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v docker) ]; then
        echo "you need to install docker as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v oras) ]; then
        echo "you need to install oras as a prerequisite to running the tests" >&3
        return 1
    fi
}

function setup_file() {
    # verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Setup nats server
    nats_server_port=$(get_free_port)
    nats_server_start nats_server_local_lint ${nats_server_port}
    echo ${nats_server_port} > ${BATS_FILE_TMPDIR}/nats_server.port

    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20

    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    mkdir -p ${zot_root_dir}
    mkdir -p ${oci_data_dir}
    zot_port=$(get_free_port)
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}"
    },
    "log": {
        "level": "debug",
        "output": "${BATS_FILE_TMPDIR}/zot.log"
    },
    "extensions": {
        "lint": {
            "enable": true,
            "mandatoryAnnotations": ["event-test"]
        },
        "events": {
            "enable": true,
            "sinks": [{
                "type": "nats",
                "address": "nats://127.0.0.1:${nats_server_port}",
                "timeout": "5s",
                "channel": "zot.test",
                "credentials": {
                   "username": "jane.joe",
                   "password": "opensesame"
                }
            }]
        }
    }
}
EOF
    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}
}

function teardown_file() {
    zot_stop_all
    nats_server_stop nats_server_local_lint
}

@test "nats/publish image lint failure event" {
    nats_server_port=$(cat ${BATS_FILE_TMPDIR}/nats_server.port)
    zot_port=$(cat ${BATS_FILE_TMPDIR}/zot.port)
    output_path=${BATS_FILE_TMPDIR}/events/lint_failure

    # Wait for event
    run wait_event_on_subject "zot.test" ${nats_server_port} ${output_path} 2
    [ "$status" -eq 0 ]

    # Create dummy config
    echo '{}' > config.json

    # Create dummy layer
    echo "this is a bogus artifact" > artifact.txt

    # Push using oras with intentionally broken config + type
    run oras push --plain-http 127.0.0.1:${zot_port}/test-artifact:v0 \
        --config config.json:application/vnd.oci.image.config.v1+json \
        artifact.txt:text/plain -d -v

    rm -f artifact.txt config.json

    # Check the correct number of events were generated
    count=$(find "${output_path}" -type f | wc -l)
    [ "$count" -eq 2 ]

    # Validate the event
    result=$(jq '.Data | @base64d | fromjson' ${output_path}/2.json)
    echo $result
    [ $(echo "${result}" | jq -r '.type') = "zotregistry.image.lint_failed" ]
    [ $(echo "${result}" | jq -r '.data.name') = "test-artifact" ]
    [ $(echo "${result}" | jq -r '.data.reference') = "v0" ]
}

@test "nats/publish image with annotations" {
    nats_server_port=$(cat ${BATS_FILE_TMPDIR}/nats_server.port)
    zot_port=$(cat ${BATS_FILE_TMPDIR}/zot.port)
    output_path=${BATS_FILE_TMPDIR}/events/lint_success

    # Wait for event
    run wait_event_on_subject "zot.test" ${nats_server_port} ${output_path} 1
    [ "$status" -eq 0 ]

    # Create dummy config
    echo '{}' > config.json

    # Create dummy layer
    echo "this is a bogus artifact" > artifact.txt

    # Push using oras with intentionally broken config + type
    run oras push --plain-http 127.0.0.1:${zot_port}/test-artifact:v1 \
        --annotation "event-test=true" \
        --config config.json:application/vnd.oci.image.config.v1+json \
        artifact.txt:text/plain -d -v

    rm -f artifact.txt config.json

    # Check the correct number of events were generated
    count=$(find "${output_path}" -type f | wc -l)
    [ "$count" -eq 1 ]

    # Validate the event
    result=$(jq '.Data | @base64d | fromjson' ${output_path}/1.json)
    [ $(echo "${result}" | jq -r '.type') = "zotregistry.image.updated" ]
    [ $(echo "${result}" | jq -r '.data.name') = "test-artifact" ]
    [ $(echo "${result}" | jq -r '.data.reference') = "v1" ]
}
