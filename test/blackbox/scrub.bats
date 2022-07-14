load helpers_scrub

function setup_file(){
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.17 oci:${TEST_DATA_DIR}/golang:1.17
}

function setup() {

    # verify prerequisites are available
    if ! verify_prerequisites; then
        echo "oh noooooo"
        exit 1
    fi

    # Setup zot server
    ZOT_ROOT_DIR=${BATS_FILE_TMPDIR}/zot
    echo ${ZOT_ROOT_DIR}
    ZOT_LOG_FILE=${ZOT_ROOT_DIR}/zot-log.json
    ZOT_CONFIG_FILE=${BATS_FILE_TMPDIR}/zot_config.json
    mkdir -p ${ZOT_ROOT_DIR}
    touch ${ZOT_LOG_FILE}
    cat >${ZOT_CONFIG_FILE} <<EOF
{
    "distSpecVersion": "1.0.1",
    "storage": {
        "rootDirectory": "${ZOT_ROOT_DIR}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8080"
    },
    "log": {
        "level": "debug",
        "output": "${ZOT_LOG_FILE}"
    },
    "extensions": {
        "scrub": {
            "interval": "2h"
        }
    }
}
EOF
    
}

function teardown() {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    teardown_zot_file_level
    rm -rf ${zot_root_dir}
}



@test "blobs/manifest integrity not affected" {

    add_test_files
    echo ${ZOT_CONFIG_FILE}
    setup_zot_file_level ${ZOT_CONFIG_FILE}
    wait_zot_reachable "http://127.0.0.1:8080/v2/_catalog"

    # wait for scrub to be done and logs to get populated
    run sleep 5s
    run not_affected
    [ "$status" -eq 0 ]
    [ $(echo "${lines[0]}" ) = 'true' ]
}

@test "blobs/manifest integrity affected" {

    add_test_files
    delete_blob
    echo ${ZOT_CONFIG_FILE}
    setup_zot_file_level ${ZOT_CONFIG_FILE}
    wait_zot_reachable "http://127.0.0.1:8080/v2/_catalog"

    # wait for scrub to be done and logs to get populated
    run sleep 5s
    run affected
    [ "$status" -eq 0 ]
    [ $(echo "${lines[0]}" ) = 'true' ]
    # [ $(echo "${lines[-1]}" | jq .) ]
}

