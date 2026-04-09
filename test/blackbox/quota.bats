# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load ../port_helper

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

    # Setup zot server with maxRepos=2
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    mkdir -p ${zot_root_dir}
    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}",
        "maxRepos": 2
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}"
    },
    "log": {
        "level": "debug",
        "output": "${BATS_FILE_TMPDIR}/zot.log"
    }
}
EOF
    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}
}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot.log
}

function teardown_file() {
    zot_stop_all
}

@test "push first image to repo1 succeeds" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/repo1:v1
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories | length') -eq 1 ]
}

@test "push second image to repo2 succeeds" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/repo2:v1
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories | length') -eq 2 ]
}

@test "push manifest to new repo3 returns HTTP 429 when quota is reached" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    # Push a minimal OCI manifest; the quota middleware rejects it before content validation
    MINIMAL_MANIFEST='{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:44136fa355ba77b9ad7b468a8c5e4f9b85d40e49c15ebd6a4e40ac9eb25c6a80","size":2},"layers":[]}'
    run curl -s -o /dev/null -w "%{http_code}" \
        -X PUT \
        -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
        -d "${MINIMAL_MANIFEST}" \
        "http://127.0.0.1:${zot_port}/v2/repo3/manifests/v1"
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" -eq 429 ]
}

@test "429 response body contains TOOMANYREQUESTS code and limit detail" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    MINIMAL_MANIFEST='{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:44136fa355ba77b9ad7b468a8c5e4f9b85d40e49c15ebd6a4e40ac9eb25c6a80","size":2},"layers":[]}'
    run curl -s \
        -X PUT \
        -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
        -d "${MINIMAL_MANIFEST}" \
        "http://127.0.0.1:${zot_port}/v2/repo3/manifests/v1"
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq -r '.errors[0].code') = "TOOMANYREQUESTS" ]
    [ $(echo "${lines[-1]}" | jq -r '.errors[0].detail.limit') = "2" ]
}

@test "push new tag to existing repo1 at limit succeeds" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/repo1:v2
    [ "$status" -eq 0 ]
}
