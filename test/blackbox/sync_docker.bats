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
        "level": "debug",
        "output": "/tmp/blackbox.log"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "https://docker.io/library"
                    ],
                    "content": [
						{
							"prefix": "registry"
						},
                        {
							"prefix": "archlinux"
						}
					],
                    "onDemand": true,
                    "tlsVerify": true
                },
                {
                    "urls": [
                        "https://registry.k8s.io"
                    ],
                    "content": [
						{
							"prefix": "kube-apiserver"
						},
                        {
							"prefix": "pause"
						},
                        {
                            "prefix": "kube-apiserver-amd64"
                        }
					],
                    "onDemand": true,
                    "tlsVerify": true
                },
                {
                    "urls": [
                        "https://public.ecr.aws"
                    ],
                    "content": [
						{
							"prefix": "amazonlinux/amazonlinux"
						}
					],
                    "onDemand": true,
                    "tlsVerify": true
                },
                {
                    "urls": [
                        "https://gcr.io"

                    ],
                    "content": [
						{
							"prefix": "google-containers/kube-proxy-amd64"
						}
					],
                    "onDemand": true,
                    "tlsVerify": true
                },
                {
                    "urls": [
                        "https://mcr.microsoft.com"
                    ],
                    "content": [
						{
							"prefix": "azure-cognitive-services/vision/spatial-analysis/diagnostics"
						}
					],
                    "onDemand": true,
                    "tlsVerify": true
                },
                {
                    "urls": [
                        "https://registry.gitlab.com"
                    ],
                    "content": [
                        {
                            "prefix": "gitlab-org/public-image-archive/gitlab-ee"
                        }
                    ],
                    "onDemand": true,
                    "tlsVerify": true
                },
                {
                    "urls": [
                        "https://quay.io"
                    ],
                    "content": [
                        {
                            "prefix": "coreos/etcd"
                        }
                    ],
                    "onDemand": true,
                    "tlsVerify": true
                },
                {
                    "urls": [
                        "https://ghcr.io"
                    ],
                    "content": [
                        {
                            "prefix": "project-zot/zot-linux-amd64"
                        }
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

    # make sure image is skipped when synced again
    run skopeo --insecure-policy copy --multi-arch=all --src-tls-verify=false \
        docker://127.0.0.1:8090/registry \
        oci:${TEST_DATA_DIR}
    [ "$status" -eq 0 ]

    run $("cat /tmp/blackbox.log | grep -q registry:latest.*.skipping image because it's already synced")
    [ "$status" -eq 0 ]
}

@test "sync docker image on demand" {
    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:8090/archlinux \
        oci:${TEST_DATA_DIR}
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[0]') = '"archlinux"' ]
    run curl http://127.0.0.1:8090/v2/archlinux/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]

    # make sure image is skipped when synced again
    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:8090/archlinux \
        oci:${TEST_DATA_DIR}
    [ "$status" -eq 0 ]

    run $("cat /tmp/blackbox.log | grep -q archlinux:latest.*.skipping image because it's already synced")
    [ "$status" -eq 0 ]
}

@test "sync k8s image list on demand" {
    run skopeo --insecure-policy copy --multi-arch=all --src-tls-verify=false \
        docker://127.0.0.1:8090/kube-apiserver:v1.26.0 \
        oci:${TEST_DATA_DIR}
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[1]') = '"kube-apiserver"' ]
    run curl http://127.0.0.1:8090/v2/kube-apiserver/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"v1.26.0"' ]
}

@test "sync k8s image on demand" {
    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:8090/pause \
        oci:${TEST_DATA_DIR}
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[2]') = '"pause"' ]
    run curl http://127.0.0.1:8090/v2/pause/tags/list
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
    run skopeo copy docker://127.0.0.1:8090/amazonlinux/amazonlinux:latest oci:${TEST_DATA_DIR} --src-tls-verify=false
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "amazonlinux/amazonlinux"))' | jq '.[]') = '"amazonlinux/amazonlinux"' ]
    run curl http://127.0.0.1:8090/v2/amazonlinux/amazonlinux/tags/list
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

@test "sync image on demand from registry.gitlab.com" {
    run skopeo copy docker://127.0.0.1:8090/gitlab-org/public-image-archive/gitlab-ee:15.11.6-ee.0 oci:${TEST_DATA_DIR} --src-tls-verify=false
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "gitlab-org/public-image-archive/gitlab-ee"))' | jq '.[]') = '"gitlab-org/public-image-archive/gitlab-ee"' ]
    run curl http://127.0.0.1:8090/v2/gitlab-org/public-image-archive/gitlab-ee/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"15.11.6-ee.0"' ]
}

@test "sync image on demand from quay.io" {
    run skopeo copy docker://127.0.0.1:8090/coreos/etcd:v3.4.26 oci:${TEST_DATA_DIR} --src-tls-verify=false
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "coreos/etcd"))' | jq '.[]') = '"coreos/etcd"' ]
    run curl http://127.0.0.1:8090/v2/coreos/etcd/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"v3.4.26"' ]
}

@test "sync image on demand from ghcr.io" {
    run skopeo copy docker://127.0.0.1:8090/project-zot/zot-linux-amd64:v2.0.0-rc5 oci:${TEST_DATA_DIR} --src-tls-verify=false
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "project-zot/zot-linux-amd64"))' | jq '.[]') = '"project-zot/zot-linux-amd64"' ]
    run curl http://127.0.0.1:8090/v2/project-zot/zot-linux-amd64/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"v2.0.0-rc5"' ]
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
    run docker run -d 127.0.0.1:8090/amazonlinux/amazonlinux:latest
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "amazonlinux/amazonlinux"))' | jq '.[]') = '"amazonlinux/amazonlinux"' ]
    run curl http://127.0.0.1:8090/v2/amazonlinux/amazonlinux/tags/list
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

@test "run docker with image synced from registry.gitlab.com" {
    run docker run -d 127.0.0.1:8090/gitlab-org/public-image-archive/gitlab-ee:15.11.6-ee.0
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "gitlab-org/public-image-archive/gitlab-ee"))' | jq '.[]') = '"gitlab-org/public-image-archive/gitlab-ee"' ]
    run curl http://127.0.0.1:8090/v2/gitlab-org/public-image-archive/gitlab-ee/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"15.11.6-ee.0"' ]
}

@test "run docker with image synced from quay.io" {
    run docker run -d 127.0.0.1:8090/coreos/etcd:v3.4.26
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "coreos/etcd"))' | jq '.[]') = '"coreos/etcd"' ]
    run curl http://127.0.0.1:8090/v2/coreos/etcd/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"v3.4.26"' ]
}

@test "run docker with image synced from ghcr.io" {
    run docker run -d 127.0.0.1:8090/project-zot/zot-linux-amd64:v2.0.0-rc5
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}"| jq '.repositories | map(select(. == "project-zot/zot-linux-amd64"))' | jq '.[]') = '"project-zot/zot-linux-amd64"' ]
    run curl http://127.0.0.1:8090/v2/project-zot/zot-linux-amd64/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"v2.0.0-rc5"' ]
}
