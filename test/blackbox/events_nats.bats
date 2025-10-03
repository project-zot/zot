# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_events
load ../port_helper

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
}

function setup_file() {
    # verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Setup nats server
    nats_server_port=$(get_free_port_for_service "nats")
    nats_server_start nats_server_local ${nats_server_port}
    echo ${nats_server_port} > ${BATS_FILE_TMPDIR}/nats_server.port

    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20

    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    mkdir -p ${zot_root_dir}
    mkdir -p ${oci_data_dir}
    zot_port=$(get_free_port_for_service "zot")
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
    nats_server_stop nats_server_local
}

@test "nats/publish repository created event" {
    nats_server_port=$(cat ${BATS_FILE_TMPDIR}/nats_server.port)
    zot_port=$(cat ${BATS_FILE_TMPDIR}/zot.port)
    output_path=${BATS_FILE_TMPDIR}/events/repository_created

    # Wait for event
    run wait_event_on_subject "zot.test" ${nats_server_port} ${output_path}
    [ "$status" -eq 0 ]

    # Push a new image and create repository
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 0 ]

    # Check the correct number of events were generated
    count=$(find "${output_path}" -type f | wc -l)
    [ "$count" -eq 1 ]

    result=$(jq '.Data | @base64d | fromjson' ${output_path}/1.json)
    [ $(echo "${result}" | jq -r '.type') = "zotregistry.repository.created" ]
    [ $(echo "${result}" | jq -r '.data.name') = "golang" ]
}

@test "nats/publish image updated event" {
    nats_server_port=$(cat ${BATS_FILE_TMPDIR}/nats_server.port)
    zot_port=$(cat ${BATS_FILE_TMPDIR}/zot.port)
    output_path=${BATS_FILE_TMPDIR}/events/updated

    # Wait for event
    run wait_event_on_subject "zot.test" ${nats_server_port} ${output_path}
    [ "$status" -eq 0 ]

    # Push a new image tag
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/golang:latest
    [ "$status" -eq 0 ]

    # Check the correct number of events were generated
    count=$(find "${output_path}" -type f | wc -l)
    [ "$count" -eq 1 ]

    # Validate the event
    result=$(jq '.Data | @base64d | fromjson' ${output_path}/1.json)
    [ $(echo "${result}" | jq -r '.type') = "zotregistry.image.updated" ]
    [ $(echo "${result}" | jq -r '.data.name') = "golang" ]
    [ $(echo "${result}" | jq -r '.data.reference') = "latest" ]
}

@test "nats/publish image deleted event" {
    nats_server_port=$(cat ${BATS_FILE_TMPDIR}/nats_server.port)
    zot_port=$(cat ${BATS_FILE_TMPDIR}/zot.port)
    output_path=${BATS_FILE_TMPDIR}/events/deleted

    # Wait for event
    run wait_event_on_subject "zot.test" ${nats_server_port} ${output_path}
    [ "$status" -eq 0 ]

    # Delete the tag
    run curl -X DELETE  http://localhost:${zot_port}/v2/golang/manifests/latest
    [ "$status" -eq 0 ]

    # Check the correct number of events were generated
    count=$(find "${output_path}" -type f | wc -l)
    [ "$count" -eq 1 ]

    # Validate the event
    result=$(jq '.Data | @base64d | fromjson' ${output_path}/1.json)
    [ $(echo "${result}" | jq -r '.type') = "zotregistry.image.deleted" ]
    [ $(echo "${result}" | jq -r '.data.name') = "golang" ]
    [ $(echo "${result}" | jq -r '.data.reference') = "latest" ]
}