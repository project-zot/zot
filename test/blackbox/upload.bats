load helpers

function setup_file() {
    # Download test data
    skopeo --insecure-policy copy docker://public.ecr.aws/t0x7q1g8/centos:7 oci:${TEST_DATA_DIR}/zot-test:0.0.1
    skopeo --insecure-policy copy docker://public.ecr.aws/t0x7q1g8/centos:8 oci:${TEST_DATA_DIR}/zot-cve-test:0.0.1
    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    mkdir -p ${zot_root_dir}
    cat > ${zot_config_file}<<EOF
{
    "version": "0.1.0-dev",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8080",
        "ReadOnly": false
    },
    "log": {
        "level": "debug"
    }
}
EOF
    setup_zot_minimal_file_level ${zot_config_file}
    wait_zot_reachable "http://127.0.0.1:8080/v2/_catalog"
}

function teardown_file() {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    teardown_zot_file_level
    rm -rf ${zot_root_dir}
}

@test "upload image" {
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/zot-test:0.0.1 \
        docker://127.0.0.1:8080/zot-test:0.0.1
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:8080/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"zot-test"' ]
}
