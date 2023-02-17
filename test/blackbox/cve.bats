load helpers_cve

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
    mkdir -p ${zot_root_dir}
    cat >${zot_config_file} <<EOF
{
    "distSpecVersion": "1.1.0",
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
        "search": {
            "enable": true,
            "cve": {
                "updateInterval": "24h"
            }
        }
    }
}
EOF
    setup_zot_file_level ${zot_config_file}
    wait_zot_reachable "http://127.0.0.1:8080/v2/_catalog"

    # setup zli to add zot registry to configs
    local registry_name=main
    local registry_url="http://127.0.0.1:8080/"
    zli_add_config ${registry_name} ${registry_url}
}

function teardown_file() {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    teardown_zot_file_level
    rm -rf ${zot_root_dir}
}

@test "cve by image name and tag" {
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:8080/golang:1.20
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:8080/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]
    run curl http://127.0.0.1:8080/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
    run ${ZLI_PATH} cve ${REGISTRY_NAME} -I golang:1.20
    [ "$status" -eq 0 ]
}
