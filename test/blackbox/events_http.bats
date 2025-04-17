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
}

function setup_file() {
    # verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Setup http server
    http_server_port=$(get_free_port)
    http_event_dir="${BATS_FILE_TMPDIR}/http_events"
    http_server_start http_receiver "${http_server_port}" "${http_event_dir}"
    echo ${http_server_port} > ${BATS_FILE_TMPDIR}/http_server.port
    wait_for_http_server $http_server_port

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
        "events": {
            "enable": true,
            "sinks": [{
                "type": "http",
                "address": "http://127.0.0.1:${http_server_port}/events",
                "timeout": "15s",
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
    http_server_stop http_receiver
}

@test "http/publish repository created event" {
    http_server_port=$(cat ${BATS_FILE_TMPDIR}/http_server.port)
    zot_port=$(cat ${BATS_FILE_TMPDIR}/zot.port)
    output_path=${BATS_FILE_TMPDIR}/http_events

    run curl -XGET http://127.0.0.1:${http_server_port}/reset
    [ "$status" -eq 0 ]
    [ -d "${output_path}" ] && rm -f "${output_path}"/*.json

    # Push a new image and create repository
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 0 ]

    sleep 1

    # Check the correct number of events were generated
    count=$(find "${output_path}" -type f | wc -l)
    [ "$count" -eq 2 ]

    result=$(jq '.' ${output_path}/1.json)
    [ $(echo "${result}" | jq -r '.headers["Ce-Type"]') = "zotregistry.repository.created" ]
    [ $(echo "${result}" | jq -r '.body.name') = "golang" ]
}

@test "http/publish image updated event" {
    http_server_port=$(cat ${BATS_FILE_TMPDIR}/http_server.port)
    zot_port=$(cat ${BATS_FILE_TMPDIR}/zot.port)
    output_path=${BATS_FILE_TMPDIR}/http_events

    run curl -XGET http://127.0.0.1:${http_server_port}/reset
    [ "$status" -eq 0 ]
    [ -d "${output_path}" ] && rm -f "${output_path}"/*.json

    # Push a new image tag
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/golang:latest
    [ "$status" -eq 0 ]

    sleep 1

    # Check the correct number of events were generated
    count=$(find "${output_path}" -type f | wc -l)
    ls -al $output_path
    [ "$count" -eq 1 ]

    # Validate the event
    result=$(jq '.' ${output_path}/1.json)
    [ $(echo "${result}" | jq -r '.headers["Ce-Type"]') = "zotregistry.image.updated" ]
    [ $(echo "${result}" | jq -r '.body.name') = "golang" ]
    [ $(echo "${result}" | jq -r '.body.reference') = "latest" ]
}

@test "http/publish image deleted event" {
    http_server_port=$(cat ${BATS_FILE_TMPDIR}/http_server.port)
    zot_port=$(cat ${BATS_FILE_TMPDIR}/zot.port)
    output_path=${BATS_FILE_TMPDIR}/http_events

    run curl -XGET http://127.0.0.1:${http_server_port}/reset
    [ "$status" -eq 0 ]
    [ -d "${output_path}" ] && rm -f "${output_path}"/*.json

    # Delete the tag
    run curl -X DELETE  http://localhost:${zot_port}/v2/golang/manifests/latest
    [ "$status" -eq 0 ]

    sleep 1

    # Check the correct number of events were generated
    count=$(find "${output_path}" -type f | wc -l)
    ls -al $output_path
    [ "$count" -eq 1 ]

    # Validate the event
    result=$(jq '.' ${output_path}/1.json)
    [ $(echo "${result}" | jq -r '.headers["Ce-Type"]') = "zotregistry.image.deleted" ]
    [ $(echo "${result}" | jq -r '.body.name') = "golang" ]
    [ $(echo "${result}" | jq -r '.body.reference') = "latest" ]
}
