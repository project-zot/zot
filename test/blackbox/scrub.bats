# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_scrub

function verify_prerequisites() {
    return 0
}

function setup_file(){
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/test-images/alpine:3.17.3 oci:${TEST_DATA_DIR}/alpine:3.17.3
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
    zot_port=$(get_free_port)
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    mkdir -p ${ZOT_ROOT_DIR}
    touch ${ZOT_LOG_FILE}
    cat >${ZOT_CONFIG_FILE} <<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${ZOT_ROOT_DIR}",
        "dedupe": false
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}"
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
    cat ${BATS_FILE_TMPDIR}/zot/zot-log.json
    zot_stop_all
}

@test "blobs/manifest integrity not affected" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    add_test_files
    echo ${ZOT_CONFIG_FILE}
    zot_serve ${ZOT_PATH} ${ZOT_CONFIG_FILE}
    wait_zot_reachable ${zot_port}

    # wait for scrub to be done and logs to get populated
    run sleep 30s
    run not_affected
    [ "$status" -eq 0 ]
    [ $(echo "${lines[0]}" ) = 'true' ]
}

@test "blobs/manifest integrity affected" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    add_test_files
    delete_blob
    echo ${ZOT_CONFIG_FILE}
    zot_serve ${ZOT_PATH} ${ZOT_CONFIG_FILE}
    wait_zot_reachable ${zot_port}

    # wait for scrub to be done and logs to get populated
    run sleep 30s
    run affected
    [ "$status" -eq 0 ]
    [ $(echo "${lines[0]}" ) = 'true' ]
}

