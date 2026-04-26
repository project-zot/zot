# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_pushpull
load ../port_helper

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
    ZOT_LOG_FILE=${zot_root_dir}/zot-log.json
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    mkdir -p ${zot_root_dir}
    mkdir -p ${oci_data_dir}
    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    touch ${ZOT_LOG_FILE}
    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}"
    },
    "log": {
        "level": "debug",
        "output": "${ZOT_LOG_FILE}"
    }
}
EOF
    export GODEBUG="fips140=only"
    git -C ${BATS_FILE_TMPDIR} clone https://github.com/project-zot/helm-charts.git
    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}
    log_output | jq 'contains("fips140 is currently enabled")?' | grep true
}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot/zot-log.json
}

function teardown_file() {
    zot_stop_all
    unset GODEBUG
}

@test "push image" {
    helper_push_image golang 1.20
}

@test "pull image" {
    helper_pull_image golang 1.20
}

@test "push image index" {
    helper_push_image_index docker://public.ecr.aws/docker/library/busybox:latest busybox latest
}

@test "pull image index" {
    helper_pull_image_index_and_delete busybox latest
}

@test "push oras artifact" {
    helper_push_oras_artifact hello-artifact v2
}

@test "pull oras artifact" {
    helper_pull_oras_artifact hello-artifact v2
}

@test "attach oras artifacts" {
    helper_attach_oras_artifacts golang 1.20
}

@test "discover oras artifacts" {
    helper_discover_oras_artifacts golang 1.20 2
}

@test "add and list tags using oras" {
    helper_add_and_list_tags_using_oras
}

@test "push helm chart" {
    helper_push_helm_chart
}

@test "pull helm chart" {
    helper_pull_helm_chart
}

@test "push image with regclient" {
    helper_push_image_with_regclient
}

@test "pull image with regclient" {
    helper_pull_image_with_regclient
}

@test "list repositories with regclient" {
    helper_list_repositories_with_regclient_pagination 2 busybox golang "-2:busybox" "-1:golang"
}

@test "list image tags with regclient" {
    helper_list_image_tags_with_regclient
}

@test "push manifest with regclient" {
    helper_push_manifest_with_regclient
}

@test "pull manifest with regclient" {
    helper_pull_manifest_with_regclient
}

@test "pull manifest with docker client" {
    helper_pull_manifest_with_docker_client
}

@test "pull manifest with crictl" {
    helper_pull_manifest_with_crictl
}

@test "push OCI artifact with regclient" {
    helper_push_oci_artifact_with_regclient
}

@test "pull OCI artifact with regclient" {
    helper_pull_oci_artifact_with_regclient
}

@test "push OCI artifact references with regclient" {
    helper_push_oci_artifact_references_with_regclient 0
}

@test "pull OCI artifact references with regclient" {
    helper_pull_oci_artifact_references_with_regclient 1
}

@test "push docker image" {
    helper_push_docker_image
}
