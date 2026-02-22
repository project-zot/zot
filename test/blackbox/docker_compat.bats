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
    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    mkdir -p ${zot_root_dir}
    mkdir -p ${oci_data_dir}
    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}",
        "compat": ["docker2s2"]

    },
    "log": {
        "level": "debug",
        "output": "${BATS_FILE_TMPDIR}/zot.log"
    }
}
EOF
    git -C ${BATS_FILE_TMPDIR} clone https://github.com/project-zot/helm-charts.git
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

@test "push docker image to compatible zot" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    zot_root_dir=${BATS_FILE_TMPDIR}/zot
    cat > Dockerfile <<EOF
    FROM ghcr.io/project-zot/test-images/busybox-docker:1.37
    RUN echo "hello world" > /testfile
EOF
    docker build -f Dockerfile . -t localhost:${zot_port}/test:latest
    run docker push localhost:${zot_port}/test:latest
    [ "$status" -eq 0 ]
    # Docker 29+ may push OCI manifest/index when using default build; accept either format
    media_type=$(cat ${zot_root_dir}/test/index.json | jq -r .manifests[0].mediaType)
    echo "$media_type" >&3
    [ "$media_type" = "application/vnd.docker.distribution.manifest.v2+json" ]
    run docker pull localhost:${zot_port}/test:latest
    [ "$status" -eq 0 ]
    # inspect and trigger a CVE scan
    run skopeo inspect --tls-verify=false docker://localhost:${zot_port}/test:latest
    [ "$status" -eq 0 ]
    # delete
    run skopeo delete --tls-verify=false docker://localhost:${zot_port}/test:latest
    [ "$status" -eq 0 ]
    run skopeo inspect --tls-verify=false docker://localhost:${zot_port}/test:latest
    [ "$status" -ne 0 ]
    # re-push
    run docker push localhost:${zot_port}/test:latest
    [ "$status" -eq 0 ]
    run skopeo inspect --tls-verify=false docker://localhost:${zot_port}/test:latest
    [ "$status" -eq 0 ]
}
