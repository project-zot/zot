# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_metrics

function verify_prerequisites() {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v htpasswd) ]; then
        echo "you need to install htpasswd as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function setup_file() {
    # verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Setup zot server
    zot_root_dir=${BATS_FILE_TMPDIR}/zot
    echo ${zot_root_dir} >&3
    zot_log_file=${zot_root_dir}/zot-log.json
    zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    zot_htpasswd_file=${BATS_FILE_TMPDIR}/zot_htpasswd
    htpasswd -Bbn ${AUTH_USER} ${AUTH_PASS} >> ${zot_htpasswd_file}

    mkdir -p ${zot_root_dir}
    touch ${zot_log_file}
    cat >${zot_config_file} <<EOF
{
    "distSpecVersion": "1.1.0-dev",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8080",
        "auth": {
            "htpasswd": {
                "path": "${zot_htpasswd_file}"
            }
        }
    },
    "log": {
        "level": "debug",
        "output": "${zot_log_file}"
    }
}
EOF

    zot_serve ${ZOT_MINIMAL_PATH} ${zot_config_file}
    wait_zot_reachable 8080

}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot/zot-log.json
}

function teardown_file() {
    zot_stop_all
}

@test "unauthorized request to metrics" {
    run metrics_route_check 8080 "" 401
    [ "$status" -eq 0 ]
    run metrics_route_check 8080 "-u test:wrongpass" 401
    [ "$status" -eq 0 ]
}

@test "authorized request: metrics enabled" {
    run metrics_route_check 8080 "-u ${AUTH_USER}:${AUTH_PASS}" 200
    [ "$status" -eq 0 ]
}