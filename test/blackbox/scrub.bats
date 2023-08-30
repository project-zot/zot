# Note: Intended to be run as "make test-bats-scrub" or "make test-bats-scrub-verbose"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_scrub

function verify_prerequisites() {
    return 0
}

function setup_file(){
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20
}

function setup() {
    # verify prerequisites are available
    if ! $(verify_prerequisites); then
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
    "distSpecVersion": "1.1.0-dev",
    "storage": {
        "rootDirectory": "${ZOT_ROOT_DIR}",
        "dedupe": false
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
            "enable": true,
            "interval": "2h"
        }
    }
}
EOF

}

function teardown() {
    zot_stop_all
}



@test "blobs/manifest integrity not affected" {
    add_test_files
    echo ${ZOT_CONFIG_FILE}
    zot_serve ${ZOT_PATH} ${ZOT_CONFIG_FILE}
    wait_zot_reachable 8080

    # wait for scrub to be done and logs to get populated
    run sleep 15s
    run not_affected
    [ "$status" -eq 0 ]
    [ $(echo "${lines[0]}" ) = 'true' ]
}

@test "blobs/manifest integrity affected" {
    add_test_files
    delete_blob
    echo ${ZOT_CONFIG_FILE}
    zot_serve ${ZOT_PATH} ${ZOT_CONFIG_FILE}
    wait_zot_reachable 8080

    # wait for scrub to be done and logs to get populated
    run sleep 15s
    run affected
    [ "$status" -eq 0 ]
    [ $(echo "${lines[0]}" ) = 'true' ]
}

