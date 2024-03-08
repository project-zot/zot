# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot

function verify_prerequisites {
    if [ ! $(command -v regctl) ]; then
        echo "you need to install regctl as a prerequisite to running the tests" >&3
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
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    mkdir -p ${zot_root_dir}
    mkdir -p ${oci_data_dir}
    zot_port=$(get_free_port)
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
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

@test "push linux/amd64 image" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    echo "Pushing ghcr.io/project-zot/zot-minimal:latest image to local zot registry, for linux/amd64 platform"
    run regctl image copy \
      ghcr.io/project-zot/zot-minimal:latest \
      localhost:${zot_port}/test-index/zot-minimal-amd64:latest \
      --platform=linux/amd64
    [ "$status" -eq 0 ]
}

@test "push linux/arm64 image" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    echo "Pushing ghcr.io/project-zot/zot-minimal:latest image to local zot registry, for linux/arm64 platform"
    run regctl image copy \
      ghcr.io/project-zot/zot-minimal:latest \
      localhost:${zot_port}/test-index/zot-minimal-arm64:latest \
      --platform=linux/arm64
    [ "$status" -eq 0 ]
}

@test "create multi-arch index" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    echo "Creating the multi-arch zot-minimal:latest index using linux/amd64 and linux/arm64 images, in local zot registry"
    run regctl index create \
      localhost:${zot_port}/test-index/zot-minimal:latest \
      --ref=localhost:${zot_port}/test-index/zot-minimal-amd64:latest \
      --ref=localhost:${zot_port}/test-index/zot-minimal-arm64:latest \
      --digest-tags --referrers
    [ "$status" -eq 0 ]
}

@test "modify multi-arch image" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    echo "Modifying the multi-arch zot-minimal:latest image attributes in local zot registry (suitable for Docker to OCI format conversion, or better conformance, scenarios)"
    run regctl image mod \
      localhost:${zot_port}/test-index/zot-minimal:latest \
      --replace \
      --to-oci \
      --to-oci-referrers \
      --label-to-annotation \
      --annotation="[*]org.opencontainers.image.title=zot-minimal" \
      --annotation="[*]org.opencontainers.image.description=Zot OCI registry" \
      --annotation="[*]org.opencontainers.image.authors=authors@zotregistry.dev" \
      --annotation="[*]org.opencontainers.image.licenses=Apache-2.0" \
      --annotation="[*]org.opencontainers.image.url=localhost:${zot_port}/test-index/zot-minimal:latest" \
      --annotation="[*]org.opencontainers.image.source=https://github.com/project-zot/zot" \
      --annotation="[*]org.opencontainers.image.version=latest" \
      --annotation="[*]org.opencontainers.image.created=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    [ "$status" -eq 0 ]
}
