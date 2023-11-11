# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_wait

function verify_prerequisites() {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v jq) ]; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v docker) ]; then
        echo "you need to install docker as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function setup_file() {
    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_sync_config_file=${BATS_FILE_TMPDIR}/zot_sync_config.json
    local ZOT_LOG_FILE=${BATS_FILE_TMPDIR}/zot.log

    mkdir -p ${zot_root_dir}

    cat >${zot_sync_config_file} <<EOF
{
    "distSpecVersion": "1.1.0-dev",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8090"
    },
    "log": {
        "level": "debug",
        "output": "${ZOT_LOG_FILE}"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "https://index.docker.io"
                    ],
                    "content": [
                        {
                            "images": {"registry": ["latest"]}
                        },
                        {
                            "images": {"archlinux": ["latest"]}
                        }
                    ],
                    "PollInterval": "10m",
                    "onDemand": false,
                    "tlsVerify": true
                },
                {
                    "urls": [
                        "https://registry.k8s.io"
                    ],
                    "content": [
                        {
                            "images": {"kube-apiserver": ["v1.26.0"]}
                        },
                        {
                            "images": {"pause": ["latest"]}
                        },
                        {
                            "images": {"kube-apiserver-amd64": ["v1.10.0"]}
                        }
                    ],
                    "PollInterval": "10m",
                    "onDemand": false,
                    "tlsVerify": true
                },
                {
                    "urls": [
                        "https://public.ecr.aws"
                    ],
                    "content": [
                        {
                            "images": {"amazonlinux/amazonlinux": ["latest"]}
                        }
                    ],
                    "PollInterval": "10m",
                    "onDemand": false,
                    "tlsVerify": true
                },
                {
                    "urls": [
                        "https://gcr.io"
                    ],
                    "content": [
                        {
                            "images": {"google-containers/kube-proxy-amd64": ["v1.17.9"]}
                        }
                    ],
                    "PollInterval": "10m",
                    "onDemand": false,
                    "tlsVerify": true
                },
                {
                    "urls": [
                        "https://mcr.microsoft.com"
                    ],
                    "content": [
                        {
                            "images": {"azure-cognitive-services/vision/spatial-analysis/diagnostics": ["latest"]}
                        }
                    ],
                    "PollInterval": "10m",
                    "onDemand": false,
                    "tlsVerify": true
                },
                {
                    "urls": [
                        "https://registry.gitlab.com"
                    ],
                    "content": [
                        {
                            "images": {"gitlab-org/public-image-archive/gitlab-ee": ["latest", "15.11.6-ee.0"]}
                        }
                    ],
                    "PollInterval": "10m",
                    "onDemand": false,
                    "tlsVerify": true
                },
                {
                    "urls": [
                        "https://quay.io"
                    ],
                    "content": [
                        {
                            "images": {"coreos/etcd": ["v3.4.26"]}
                        }
                    ],
                    "PollInterval": "10m",
                    "onDemand": false,
                    "tlsVerify": true
                },
                {
                    "urls": [
                        "https://ghcr.io"
                    ],
                    "content": [
                        {
                            "images": {"project-zot/zot-linux-amd64": ["v2.0.0-rc5"]}
                        }
                    ],
                    "PollInterval": "10m",
                    "onDemand": false,
                    "tlsVerify": true
                }
            ]
        }
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_sync_config_file}
    wait_zot_reachable 8090
}

function teardown_file() {
    zot_stop_all
}

@test "wait for sync specific images to finish" {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local ZOT_LOG_FILE=${BATS_FILE_TMPDIR}/zot.log

    echo ${ZOT_LOG_FILE} >&3

    start=`date +%s`
    echo "waiting for sync to finish" >&3

    wait_for_string_count "sync: finished syncing specific images" ${ZOT_LOG_FILE} 600 11 // repo:tag entries

    end=`date +%s`

    runtime=$((end-start))
    echo "sync finished in $runtime sec" >&3
}

# sync image
@test "check docker image list was synced" {
    run skopeo --insecure-policy copy --multi-arch=all --src-tls-verify=false \
        docker://127.0.0.1:8090/registry \
        oci:${TEST_DATA_DIR}
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/registry/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

@test "check docker image was synced" {
    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:8090/archlinux \
        oci:${TEST_DATA_DIR}
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/archlinux/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

@test "check k8s image list was synced" {
    run skopeo --insecure-policy copy --multi-arch=all --src-tls-verify=false \
        docker://127.0.0.1:8090/kube-apiserver:v1.26.0 \
        oci:${TEST_DATA_DIR}
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/kube-apiserver/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"v1.26.0"' ]
}

@test "check k8s image was synced" {
    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:8090/pause \
        oci:${TEST_DATA_DIR}
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/pause/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

@test "check registry.k8s.io image was synced" {
    run skopeo copy docker://127.0.0.1:8090/kube-apiserver-amd64:v1.10.0 oci:${TEST_DATA_DIR} --src-tls-verify=false
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/kube-apiserver-amd64/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"v1.10.0"' ]
}

@test "check aws.amazon.com/ecr images was synced" {
    run skopeo copy docker://127.0.0.1:8090/amazonlinux/amazonlinux:latest oci:${TEST_DATA_DIR} --src-tls-verify=false
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/amazonlinux/amazonlinux/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

@test "check gcr.io image was synced" {
    run skopeo copy docker://127.0.0.1:8090/google-containers/kube-proxy-amd64:v1.17.9 oci:${TEST_DATA_DIR} --src-tls-verify=false
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/google-containers/kube-proxy-amd64/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"v1.17.9"' ]
}

@test "check mcr.microsoft.com image was synced" {
    run skopeo copy docker://127.0.0.1:8090/azure-cognitive-services/vision/spatial-analysis/diagnostics:latest oci:${TEST_DATA_DIR} --src-tls-verify=false
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/azure-cognitive-services/vision/spatial-analysis/diagnostics/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

@test "check registry.gitlab.com image was synced" {
    run skopeo copy docker://127.0.0.1:8090/gitlab-org/public-image-archive/gitlab-ee:15.11.6-ee.0 oci:${TEST_DATA_DIR} --src-tls-verify=false
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/gitlab-org/public-image-archive/gitlab-ee/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"15.11.6-ee.0"' ]
}

@test "check quay.io image was synced" {
    run skopeo copy docker://127.0.0.1:8090/coreos/etcd:v3.4.26 oci:${TEST_DATA_DIR} --src-tls-verify=false
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/coreos/etcd/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"v3.4.26"' ]
}

@test "check ghcr.io image was synced" {
    run skopeo copy docker://127.0.0.1:8090/project-zot/zot-linux-amd64:v2.0.0-rc5 oci:${TEST_DATA_DIR} --src-tls-verify=false
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8090/v2/project-zot/zot-linux-amd64/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"v2.0.0-rc5"' ]
}
