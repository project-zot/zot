load helpers_pushpull

function setup_file() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20
    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    local htpasswordFile=${BATS_FILE_TMPDIR}/htpasswd
    mkdir -p ${zot_root_dir}
    mkdir -p ${oci_data_dir}
    echo 'test:$2a$10$EIIoeCnvsIDAJeDL4T1sEOnL2fWOvsq7ACZbs3RT40BBBXg.Ih7V.' >> ${htpasswordFile}
    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "127.0.0.1",
        "port": "8080",
        "auth": {
            "htpasswd": {
                "path": "${htpasswordFile}"
            }
        },
        "accessControl": {
            "**": {
                "anonymousPolicy": [ 
                    "read",
                    "create",
                    "delete",
                    "detectManifestCollision"
                ],
                "policies": [
                    {
                        "users": [
                            "test"
                        ],
                        "actions": [
                            "read",
                            "create",
                            "delete"
                        ]
                    }
                ]
            }
        }
    },
    "log": {
        "level": "debug"
    }
}
EOF
    setup_zot_file_level ${zot_config_file}
    wait_zot_reachable "http://127.0.0.1:8080/v2/_catalog"   
}

function teardown_file() {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    teardown_zot_file_level
    rm -rf ${zot_root_dir}
    rm -rf ${oci_data_dir}
}

@test "push 2 images with same manifest with user policy" {
    run skopeo --insecure-policy copy --dest-creds test:test --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:8080/golang:1.20
    [ "$status" -eq 0 ]

    run skopeo --insecure-policy copy --dest-creds test:test --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:8080/golang:latest
    [ "$status" -eq 0 ]
}

@test "skopeo delete image with anonymous policy should fail" {
    # skopeo deletes by digest, so it should fail with detectManifestCollision policy
    run skopeo --insecure-policy delete --tls-verify=false \
        docker://127.0.0.1:8080/golang:1.20
    [ "$status" -eq 1 ]
    # conflict status code
    [[ "$output" == *"409"* ]]
}

@test "regctl delete image with anonymous policy should fail" {
    run regctl registry set localhost:8080 --tls disabled
    [ "$status" -eq 0 ]

    run regctl image delete localhost:8080/golang:1.20 --force-tag-dereference
    [ "$status" -eq 1 ]
    # conflict status code
    [[ "$output" == *"409"* ]]
}

@test "delete image with user policy should work" {
    # should work without detectManifestCollision policy
    run skopeo --insecure-policy delete --creds test:test --tls-verify=false \
        docker://127.0.0.1:8080/golang:1.20
    [ "$status" -eq 0 ]
}
