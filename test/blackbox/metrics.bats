load helpers_metrics

function setup_file() {
    # verify prerequisites are available
    if ! verify_prerequisites; then
        echo "oh noooooo"
        exit 1
    fi

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.17 oci:${TEST_DATA_DIR}/golang:1.17

    # Setup zot server
    zot_root_dir=${BATS_FILE_TMPDIR}/zot
    echo ${zot_root_dir}
    zot_log_file=${zot_root_dir}/zot-log.json
    zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    mkdir -p ${zot_root_dir}
    touch ${zot_log_file}
    cat >${zot_config_file} <<EOF
{
    "distSpecVersion": "1.0.1",
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

    setup_zot_file_level ${zot_config_file}
    wait_zot_reachable "http://127.0.0.1:8080/v2/_catalog"

}

function teardown_file() {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    teardown_zot_file_level
    rm -rf ${zot_root_dir}
}

@test "metric enabled" {
    local servername="http://127.0.0.1:8080/metrics"
    status_code=$(curl --write-out '%{http_code}' --silent --output /dev/null ${servername})
    [ "$status_code" -eq 200 ]
}
