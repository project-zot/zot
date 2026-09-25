# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load ../port_helper

function verify_prerequisites() {
    if [ ! -f "${ZOT_PATH}" ]; then
        echo "you need to build zot (${ZOT_PATH}) as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function setup_file() {
    if ! verify_prerequisites; then
        exit 1
    fi

    zot_root_dir=${BATS_FILE_TMPDIR}/zot
    zot_log_file=${zot_root_dir}/zot-log.json
    zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port

    mkdir -p ${zot_root_dir}
    touch ${zot_log_file}
    cat >${zot_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "127.0.0.1",
        "port": "${zot_port}"
    },
    "log": {
        "level": "debug",
        "output": "${zot_log_file}"
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}
}

function teardown_file() {
    zot_stop_all
}

@test "healthcheck succeeds against a running server using config" {
    zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json

    run ${ZOT_PATH} healthcheck ${zot_config_file}
    [ "$status" -eq 0 ]

    run ${ZOT_PATH} healthcheck --endpoint=livez ${zot_config_file}
    [ "$status" -eq 0 ]

    run ${ZOT_PATH} healthcheck --endpoint=startupz ${zot_config_file}
    [ "$status" -eq 0 ]

    run ${ZOT_PATH} ready ${zot_config_file}
    [ "$status" -eq 0 ]
}

@test "healthcheck succeeds using --url" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`

    run ${ZOT_PATH} healthcheck --url "http://127.0.0.1:${zot_port}/readyz"
    [ "$status" -eq 0 ]
}

@test "minimal binary also supports healthcheck" {
    if [ ! -f "${ZOT_MINIMAL_PATH}" ]; then
        skip "minimal binary not built (${ZOT_MINIMAL_PATH})"
    fi

    zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json

    run ${ZOT_MINIMAL_PATH} healthcheck ${zot_config_file}
    [ "$status" -eq 0 ]
}

@test "healthcheck rejects config and --url together" {
    zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json

    run ${ZOT_PATH} healthcheck ${zot_config_file} --url "http://127.0.0.1:8080/readyz"
    [ "$status" -ne 0 ]
}

@test "healthcheck fails when the server is down" {
    zot_stop_all

    run ${ZOT_PATH} healthcheck --url "http://127.0.0.1:1/readyz" --timeout 100ms
    [ "$status" -ne 0 ]
}
