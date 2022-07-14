load helpers_sync

function setup_file() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.17 oci:${TEST_DATA_DIR}/golang:1.17
    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_minimal_root_dir=${BATS_FILE_TMPDIR}/zot-minimal
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local zot_minimal_config_file=${BATS_FILE_TMPDIR}/zot_minimal_config.json
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    mkdir -p ${zot_root_dir}
    mkdir -p ${zot_minimal_root_dir}
    mkdir -p ${oci_data_dir}
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
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:9000"
                    ],
                    "onDemand": true,
                    "tlsVerify": false,
                    "PollInterval": "20s",
                    "content": [
                        {
                            "prefix": "**"
                        }
                    ]
                }
            ]
        }
    }
}
EOF
    cat >${zot_minimal_config_file} <<EOF
{
    "distSpecVersion": "1.0.1",
    "storage": {
        "rootDirectory": "${zot_minimal_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "9000"
    },
    "log": {
        "level": "debug"
    }
}
EOF
    setup_zot_file_level ${zot_config_file}
    wait_zot_reachable "http://127.0.0.1:8080/v2/_catalog"

    setup_zot_minimal_file_level ${zot_minimal_config_file}
    wait_zot_reachable "http://127.0.0.1:9000/v2/_catalog"
}

function teardown_file() {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    local zot_minimal_root_dir=${BATS_FILE_TMPDIR}/zot-minimal
    teardown_zot_file_level
    rm -rf ${zot_root_dir}
    rm -rf ${zot_minimal_root_dir}
    rm -rf ${oci_data_dir}
}

@test "sync registry" {
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.17 \
        docker://127.0.0.1:9000/golang:1.17
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:9000/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]
    run curl http://127.0.0.1:8080/v2/_catalog
    run curl http://127.0.0.1:9000/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.17"' ]
    run sleep 30s
    run curl http://127.0.0.1:8080/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]
}
