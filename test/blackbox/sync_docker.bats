load helpers_sync

function setup_file() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi

    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_sync_ondemand_config_file=${BATS_FILE_TMPDIR}/zot_sync_ondemand_config.json

    mkdir -p ${zot_root_dir}

    cat >${zot_sync_ondemand_config_file} <<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8090"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "https://docker.io/library",
                        "https://registry.k8s.io",
                        "https://aws.amazon.com/ecr",
                        "https://gcr.io",
                        "https://mcr.microsoft.com"
                    ],
                    "onDemand": true,
                    "tlsVerify": true
                }
            ]
        }
    }
}
EOF

    setup_zot_file_level ${zot_sync_ondemand_config_file}
    wait_zot_reachable "http://127.0.0.1:8090/v2/_catalog"
}

function teardown_file() {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot

    teardown_zot_file_level
    rm -rf ${zot_root_dir}
}

# sync image
@test "sync docker image list on demand" {
    run skopeo --insecure-policy copy --multi-arch=all --src-tls-verify=false \
        docker://127.0.0.1:8090/registry \
        oci:${TEST_DATA_DIR}
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"registry"' ]
    run curl http://127.0.0.1:8090/v2/registry/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

@test "sync docker image on demand" {
    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:8090/archlinux \
        oci:${TEST_DATA_DIR}
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[0]') = '"archlinux"' ]
    run curl http://127.0.0.1:8090/v2/registry/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

@test "sync image on demand from registry.k8s.io" {
    run skopeo copy docker://127.0.0.1:8090/kube-apiserver-amd64:v1.10.0 oci:${TEST_DATA_DIR} --src-tls-verify=false
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "kube-apiserver-amd64"))' | jq '.[]') = '"kube-apiserver-amd64"' ]
    run curl http://127.0.0.1:8090/v2/kube-apiserver-amd64/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"v1.10.0"' ]
}

@test "sync image on demand from aws.amazon.com/ecr" {
    run skopeo copy docker://127.0.0.1:8090/amazonlinux:latest oci:${TEST_DATA_DIR} --src-tls-verify=false
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "amazonlinux"))' | jq '.[]') = '"amazonlinux"' ]
    run curl http://127.0.0.1:8090/v2/amazonlinux/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

@test "sync image on demand from gcr.io" {
    run skopeo copy docker://127.0.0.1:8090/google-containers/kube-proxy-amd64:v1.17.9 oci:${TEST_DATA_DIR} --src-tls-verify=false
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "google-containers/kube-proxy-amd64"))' | jq '.[]') = '"google-containers/kube-proxy-amd64"' ]
    run curl http://127.0.0.1:8090/v2/google-containers/kube-proxy-amd64/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"v1.17.9"' ]
}

@test "sync image on demand from mcr.microsoft.com" {
    run skopeo copy docker://127.0.0.1:8090/azure-cognitive-services/vision/spatial-analysis/diagnostics:latest oci:${TEST_DATA_DIR} --src-tls-verify=false
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "azure-cognitive-services/vision/spatial-analysis/diagnostics"))' | jq '.[]') = '"azure-cognitive-services/vision/spatial-analysis/diagnostics"' ]
    run curl http://127.0.0.1:8090/v2/azure-cognitive-services/vision/spatial-analysis/diagnostics/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

@test "run docker with image synced from docker.io/library" {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot 
    run rm -rf ${zot_root_dir}
    [ "$status" -eq 0 ]
    
    run docker run -d 127.0.0.1:8090/archlinux:latest
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "archlinux"))' | jq '.[]') = '"archlinux"' ]
    run curl http://127.0.0.1:8090/v2/archlinux/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]

    run docker kill $(docker ps -q)
}

@test "run docker with image synced from registry.k8s.io" {
    run docker run -d 127.0.0.1:8090/kube-apiserver-amd64:v1.10.0
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "kube-apiserver-amd64"))' | jq '.[]') = '"kube-apiserver-amd64"' ]
    run curl http://127.0.0.1:8090/v2/kube-apiserver-amd64/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"v1.10.0"' ]

    run docker kill $(docker ps -q)
}

@test "run docker with image synced from aws.amazon.com/ecr" {
    run docker run -d 127.0.0.1:8090/amazonlinux:latest
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "amazonlinux"))' | jq '.[]') = '"amazonlinux"' ]
    run curl http://127.0.0.1:8090/v2/amazonlinux/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]

    run docker kill $(docker ps -q)
}

@test "run docker with image synced from gcr.io" {
    run docker run -d 127.0.0.1:8090/google-containers/kube-proxy-amd64:v1.17.9
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "google-containers/kube-proxy-amd64"))' | jq '.[]') = '"google-containers/kube-proxy-amd64"' ]
    run curl http://127.0.0.1:8090/v2/google-containers/kube-proxy-amd64/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"v1.17.9"' ]

    run docker kill $(docker ps -q)
}

@test "run docker with image synced from mcr.microsoft.com" {
    run docker run -d 127.0.0.1:8090/azure-cognitive-services/vision/spatial-analysis/diagnostics:latest
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "azure-cognitive-services/vision/spatial-analysis/diagnostics"))' | jq '.[]') = '"azure-cognitive-services/vision/spatial-analysis/diagnostics"' ]
    run curl http://127.0.0.1:8090/v2/azure-cognitive-services/vision/spatial-analysis/diagnostics/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]

    run docker kill $(docker ps -q)
}

