# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_wait
load ../port_helper

function verify_prerequisites() {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v jq) ]; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v skopeo) ]; then
        echo "you need to install skopeo as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function setup_file() {
    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Download test image once into the suite's shared test data dir
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20

    local zot_stream_root_dir=${BATS_FILE_TMPDIR}/zot-stream-ondemand
    local zot_stream_config_file=${BATS_FILE_TMPDIR}/zot_stream_config.json

    local zot_upstream_root_dir=${BATS_FILE_TMPDIR}/zot-upstream
    local zot_upstream_config_file=${BATS_FILE_TMPDIR}/zot_upstream_config.json

    mkdir -p ${zot_stream_root_dir}
    mkdir -p ${zot_upstream_root_dir}

    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    zot_upstream_port=$(get_free_port_for_service "zot_upstream")
    echo ${zot_upstream_port} > ${BATS_FILE_TMPDIR}/zot.port_upstream

    # Downstream zot: onDemand + stream enabled, syncing from upstream
    cat >${zot_stream_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_stream_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_upstream_port}"
                    ],
                    "onDemand": true,
                    "stream": true,
                    "tlsVerify": false,
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

    # Upstream zot-minimal: holds the source image, no sync
    cat >${zot_upstream_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_upstream_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_upstream_port}"
    },
    "log": {
        "level": "debug"
    }
}
EOF

    zot_serve ${ZOT_MINIMAL_PATH} ${zot_upstream_config_file}
    wait_zot_reachable ${zot_upstream_port}

    zot_serve ${ZOT_PATH} ${zot_stream_config_file}
    wait_zot_reachable ${zot_port}
}

function teardown_file() {
    zot_stop_all
}

@test "stream on-demand pulls image manifest from upstream" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    zot_upstream_port=`cat ${BATS_FILE_TMPDIR}/zot.port_upstream`

    # Push the source image to the upstream registry
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_upstream_port}/golang:1.20
    [ "$status" -eq 0 ]

    # Upstream now lists golang
    run curl http://127.0.0.1:${zot_upstream_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]

    # Downstream initially has no repos
    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories | length') -eq 0 ]

    # First pull through downstream: triggers streamed on-demand sync
    run curl -fsS -o /dev/null -w "%{http_code}" \
        -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        -H "Accept: application/vnd.oci.image.index.v1+json" \
        http://127.0.0.1:${zot_port}/v2/golang/manifests/1.20
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" = "200" ]

    # Downstream now lists golang (the on-demand sync populated the repo)
    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]

    run curl http://127.0.0.1:${zot_port}/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
}

@test "stream on-demand caches blobs after first pull" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`

    # Fetch the manifest from the downstream to discover a blob digest.
    # The previous test already triggered the on-demand sync, so this hits the cache for the manifest.
    local manifest_file=${BATS_FILE_TMPDIR}/golang-manifest.json
    run curl -fsS \
        -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        -H "Accept: application/vnd.oci.image.index.v1+json" \
        -o ${manifest_file} \
        http://127.0.0.1:${zot_port}/v2/golang/manifests/1.20
    [ "$status" -eq 0 ]

    # If the manifest is an image index, descend one level to a platform-specific manifest.
    local media_type=$(jq -r '.mediaType // ""' ${manifest_file})
    if [ "${media_type}" = "application/vnd.oci.image.index.v1+json" ] || \
       [ "${media_type}" = "application/vnd.docker.distribution.manifest.list.v2+json" ]; then
        local child_digest=$(jq -r '.manifests[0].digest' ${manifest_file})
        run curl -fsS \
            -H "Accept: application/vnd.oci.image.manifest.v1+json" \
            -o ${manifest_file} \
            http://127.0.0.1:${zot_port}/v2/golang/manifests/${child_digest}
        [ "$status" -eq 0 ]
    fi

    # Pick the config blob digest — small, always present.
    local blob_digest=$(jq -r '.config.digest' ${manifest_file})
    [ -n "${blob_digest}" ]
    [ "${blob_digest}" != "null" ]

    # Stop the upstream so a second pull MUST come from the downstream's cache.
    # If streaming didn't actually cache, this fetch will fail.
    zot_stop_all
    zot_serve ${ZOT_PATH} ${BATS_FILE_TMPDIR}/zot_stream_config.json
    wait_zot_reachable ${zot_port}

    # Second blob pull — upstream is dead, so success proves the blob was cached.
    run curl -fsS -o /dev/null -w "%{http_code}" \
        http://127.0.0.1:${zot_port}/v2/golang/blobs/${blob_digest}
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" = "200" ]
}
