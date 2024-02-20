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
    zot_port=$(get_free_port)
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    htpasswd -Bbn ${AUTH_USER} ${AUTH_PASS} >> ${zot_htpasswd_file}
    htpasswd -Bbn ${METRICS_USER} ${METRICS_PASS} >> ${zot_htpasswd_file}

    mkdir -p ${zot_root_dir}
    touch ${zot_log_file}
    cat >${zot_config_file} <<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}",
        "auth": {
            "htpasswd": {
                "path": "${zot_htpasswd_file}"
            }
        },
        "accessControl": {
            "metrics":{
                "users": ["${METRICS_USER}"]
            },
            "repositories": {
                "**": {
                    "anonymousPolicy": [
                        "read",
                        "create"
                    ],
                    "defaultPolicy": ["read"]
                }
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
    wait_zot_reachable ${zot_port}

}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot/zot-log.json
}

function teardown_file() {
    zot_stop_all
}

@test "unauthorized request to metrics" {
# anonymous policy: metrics endpoint should not be available
# 401 - http.StatusUnauthorized
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run metrics_route_check ${zot_port} "" 401
    [ "$status" -eq 0 ]
# user is not in htpasswd
    run metrics_route_check ${zot_port} "-u test:wrongpass" 401
    [ "$status" -eq 0 ]
# proper user/pass tuple from htpasswd, but user not allowed to access metrics
# 403 - http.StatusForbidden
    run metrics_route_check ${zot_port} "-u ${AUTH_USER}:${AUTH_PASS}" 403
    [ "$status" -eq 0 ]
}

@test "authorized request: metrics enabled" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run metrics_route_check ${zot_port} "-u ${METRICS_USER}:${METRICS_PASS}" 200
    [ "$status" -eq 0 ]
}
