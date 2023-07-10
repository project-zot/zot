load helpers_sync

function setup_file() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20
    # Setup zot server
    local zot_sync_one_root_dir=${BATS_FILE_TMPDIR}/zot-one
    local zot_sync_two_root_dir=${BATS_FILE_TMPDIR}/zot-two

    local zot_sync_one_config_file=${BATS_FILE_TMPDIR}/zot_sync_one_config.json
    local zot_sync_two_config_file=${BATS_FILE_TMPDIR}/zot_sync_two_config.json

    mkdir -p ${zot_sync_one_root_dir}
    mkdir -p ${zot_sync_two_root_dir}

    cat >${zot_sync_one_config_file} <<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${zot_sync_one_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8081"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:8081",
                        "http://localhost:8082"
                    ],
                    "onDemand": false,
                    "tlsVerify": false,
                    "PollInterval": "1s",
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

    cat >${zot_sync_two_config_file} <<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${zot_sync_two_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8082"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:8081",
                        "http://localhost:8082"
                    ],
                    "onDemand": false,
                    "tlsVerify": false,
                    "PollInterval": "1s",
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

    git -C ${BATS_FILE_TMPDIR} clone https://github.com/project-zot/helm-charts.git

    setup_zot_file_level ${zot_sync_one_config_file}
    wait_zot_reachable "http://127.0.0.1:8081/v2/_catalog"

    setup_zot_file_level ${zot_sync_two_config_file}
    wait_zot_reachable "http://127.0.0.1:8082/v2/_catalog"
}

function teardown_file() {
    local zot_sync_one_root_dir=${BATS_FILE_TMPDIR}/zot-per
    local zot_sync_two_root_dir=${BATS_FILE_TMPDIR}/zot-ondemand
    teardown_zot_file_level
    rm -rf ${zot_sync_one_root_dir}
    rm -rf ${zot_sync_two_root_dir}
}

# sync image
@test "push one image to zot one, zot two should sync it" {
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:8081/golang:1.20
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:8081/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]
    run curl http://127.0.0.1:8081/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
    
    run sleep 30s
    
    run curl http://127.0.0.1:8082/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]

    run curl http://127.0.0.1:8082/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
}

@test "push one image to zot-two, zot-one should sync it" {
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:8082/anothergolang:1.20
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:8082/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[0]') = '"anothergolang"' ]
    run curl http://127.0.0.1:8082/v2/anothergolang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
    
    run sleep 30s
    
    run curl http://127.0.0.1:8081/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[0]') = '"anothergolang"' ]

    run curl http://127.0.0.1:8081/v2/anothergolang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
}
