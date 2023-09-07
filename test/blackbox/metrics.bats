# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot

function verify_prerequisites() {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function setup_file() {
    # verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20

    # Setup zot server
    zot_root_dir=${BATS_FILE_TMPDIR}/zot
    echo ${zot_root_dir}
    zot_log_file=${zot_root_dir}/zot-log.json
    zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
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
        "port": "8080"
    },
    "log": {
        "level": "debug",
        "output": "${zot_log_file}"
    },
    "extensions": {
        "metrics": {
            "enable": true,
            "prometheus": {
                "path": "/metrics"
            }
        }
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable 8080

}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot/zot-log.json
}

function teardown_file() {
    zot_stop_all
}

@test "metric enabled" {
    local servername="http://127.0.0.1:8080/metrics"
    status_code=$(curl --write-out '%{http_code}' --silent --output /dev/null ${servername})
    [ "$status_code" -eq 200 ]
}
