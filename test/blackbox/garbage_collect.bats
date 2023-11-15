load helpers_zot

function verify_prerequisites {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v jq) ]; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function setup_file() {
    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20
    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    zot_port=$(get_free_port)
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    mkdir -p ${zot_root_dir}
    mkdir -p ${oci_data_dir}
    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${zot_root_dir}",
        "gc": true,
        "gcDelay": "30s",
        "gcInterval": "1s",
        "retention": {
            "delay": "40s",
            "policies": [
                {
                    "repositories": ["**"],
                    "deleteReferrers": true,
                    "deleteUntagged": true
                }
            ]
        }
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}"
    },
    "log": {
        "level": "debug",
        "output": "${BATS_FILE_TMPDIR}/gc.log"
    }
}
EOF
    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}
}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from from teardown_file
    cat ${BATS_FILE_TMPDIR}/gc.log
}

function teardown_file() {
    zot_stop_all
}

@test "push image" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]
    run curl http://127.0.0.1:${zot_port}/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
}

@test "push image index" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    # --multi-arch below pushes an image index (containing many images) instead
    # of an image manifest (single image)
    run skopeo --insecure-policy copy --format=oci --dest-tls-verify=false --multi-arch=all \
        docker://public.ecr.aws/docker/library/busybox:latest \
        docker://127.0.0.1:${zot_port}/busybox:latest
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[0]') = '"busybox"' ]
    run curl http://127.0.0.1:${zot_port}/v2/busybox/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

@test "attach oras artifacts" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    # attach signature to image
    echo "{\"artifact\": \"\", \"signature\": \"pat hancock\"}" > signature.json
    run oras attach --plain-http 127.0.0.1:${zot_port}/golang:1.20 --image-spec v1.1-image --artifact-type 'signature/example' ./signature.json:application/json
    [ "$status" -eq 0 ]
    # attach sbom to image
    echo "{\"version\": \"0.0.0.0\", \"artifact\": \"'127.0.0.1:${zot_port}/golang:1.20'\", \"contents\": \"good\"}" > sbom.json
    run oras attach --plain-http 127.0.0.1:${zot_port}/golang:1.20 --image-spec v1.1-image --artifact-type 'sbom/example' ./sbom.json:application/json
    [ "$status" -eq 0 ]

    # attach signature to index image
    run oras attach --plain-http 127.0.0.1:${zot_port}/busybox:latest --image-spec v1.1-image --artifact-type 'signature/example' ./signature.json:application/json
    [ "$status" -eq 0 ]
    # attach sbom to index image
    echo "{\"version\": \"0.0.0.0\", \"artifact\": \"'127.0.0.1:${zot_port}/golang:1.20'\", \"contents\": \"good\"}" > sbom.json
    run oras attach --plain-http 127.0.0.1:${zot_port}/busybox:latest --image-spec v1.1-image --artifact-type 'sbom/example' ./sbom.json:application/json
    [ "$status" -eq 0 ]
}

@test "push OCI artifact with regclient" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set 127.0.0.1:${zot_port} --tls disabled
    [ "$status" -eq 0 ]

    run regctl artifact put --artifact-type application/vnd.example.artifact --subject 127.0.0.1:${zot_port}/golang:1.20 <<EOF
this is an artifact
EOF
    [ "$status" -eq 0 ]

    run regctl artifact get --subject 127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 0 ]

    run regctl artifact put --artifact-type application/vnd.example.artifact --subject 127.0.0.1:${zot_port}/busybox:latest <<EOF
this is an artifact
EOF
    [ "$status" -eq 0 ]

    run regctl artifact get --subject 127.0.0.1:${zot_port}/busybox:latest
    [ "$status" -eq 0 ]
}

@test "garbage collect all artifacts after image delete" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy delete --tls-verify=false \
        docker://127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 0 ]

    run skopeo --insecure-policy delete --tls-verify=false \
        docker://127.0.0.1:${zot_port}/busybox:latest
    [ "$status" -eq 0 ]

    # sleep past gc delay
    sleep 100

    # gc should have removed artifacts
    run regctl artifact get --subject 127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 1 ]

    run regctl artifact get --subject 127.0.0.1:${zot_port}/busybox:latest
    [ "$status" -eq 1 ]

    run oras discover --plain-http -o json 127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 1 ]

    run oras discover --plain-http -o json 127.0.0.1:${zot_port}/busybox:latest
    [ "$status" -eq 1 ]

    # repos should also be gc'ed
    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq -r '.repositories | length') -eq 0 ]
}


