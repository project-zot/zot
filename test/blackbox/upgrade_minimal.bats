# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_pushpull
load ../port_helper

function setup_file() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi
    pushpull_isolate_regctl_config
    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20
    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    mkdir -p ${zot_root_dir}
    mkdir -p ${oci_data_dir}
    touch "${zot_root_dir}/zot-log.json"
    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    cat > ${zot_config_file}<<JSON
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
        "output": "${zot_root_dir}/zot-log.json"
    }
}
JSON
    git -C ${BATS_FILE_TMPDIR} clone https://github.com/project-zot/helm-charts.git
    zot_rel_min_serve ${zot_config_file}
    wait_zot_reachable ${zot_port}
}


function teardown() {
    # conditionally printing on failure is possible from teardown but not from teardown_file
    [ -f "${BATS_FILE_TMPDIR}/zot/zot-log.json" ] && cat "${BATS_FILE_TMPDIR}/zot/zot-log.json"
}

function teardown_file() {
    zot_stop_all
}

# ==============================================================================
# RELEASE TESTS - Test released version before upgrade
# ==============================================================================

@test "[release] push image" {
    helper_push_image golang 1.20 oci:${TEST_DATA_DIR}/golang:1.20
}

@test "[release] pull image" {
    helper_pull_image golang 1.20
}

@test "[release] push image index" {
    helper_push_image_index docker://public.ecr.aws/docker/library/busybox:latest busybox latest
}

@test "[release] pull image index" {
    helper_pull_image_index busybox latest
}

@test "[release] push oras artifact" {
    helper_push_oras_artifact hello-artifact v2
}

@test "[release] pull oras artifact" {
    helper_pull_oras_artifact hello-artifact v2
}

@test "[release] attach oras artifacts" {
    helper_attach_oras_artifacts golang 1.20
}

@test "[release] discover oras artifacts" {
    helper_discover_oras_artifacts golang 1.20 2
}

@test "[release] add and list tags using oras" {
    helper_add_and_list_tags_using_oras
}

@test "[release] push helm chart" {
    helper_push_helm_chart
}

@test "[release] pull helm chart" {
    helper_pull_helm_chart
}

@test "[release] push image with regclient" {
    helper_push_image_with_regclient "ocidir://${TEST_DATA_DIR}/golang:1.20" test-regclient
}

@test "[release] pull image with regclient" {
    helper_pull_image_with_regclient test-regclient "ocidir://${TEST_DATA_DIR}/golang:1.20"
}

@test "[release] list repositories with regclient" {
    helper_list_repositories_with_regclient_pagination 2 busybox golang test-regclient "-2:busybox" "-1:golang"
}

@test "[release] list image tags with regclient" {
    helper_list_image_tags_with_regclient test-regclient
}

@test "[release] push manifest with regclient" {
    helper_push_manifest_with_regclient test-regclient 1.0.0
}

@test "[release] pull manifest with regclient" {
    helper_pull_manifest_with_regclient test-regclient
}

@test "[release] pull manifest with docker client" {
    helper_pull_manifest_with_docker_client test-regclient
}

@test "[release] pull manifest with crictl" {
    helper_pull_manifest_with_crictl test-regclient
}

@test "[release] push OCI artifact with regclient" {
    helper_push_oci_artifact_with_regclient artifact:demo
}

@test "[release] pull OCI artifact with regclient" {
    helper_pull_oci_artifact_with_regclient artifact:demo "this is an artifact"
}

@test "[release] push OCI artifact references with regclient" {
    helper_push_oci_artifact_references_with_regclient 0
}

@test "[release] pull OCI artifact references with regclient" {
    helper_pull_oci_artifact_references_with_regclient 1
}

@test "[release] build docker image and verify docker push and pull fail" {
    helper_build_docker_image_push_and_pull
}

# ==============================================================================
# UPGRADE - Switch to new binary
# ==============================================================================

@test "[upgrade] upgrade to new binary" {
    zot_stop_all
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local zot_port=$(get_zot_port)
    zot_serve ${ZOT_MINIMAL_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}
    sleep 60    # zot does additional initialization/verification during startup
}

# ==============================================================================
# NEW TESTS - Test new version after upgrade
# After upgrading to the new binary, expect additional artifacts (a signature
# and an sbom) that were attached
# ==============================================================================

@test "[new] existing pull image" {
    helper_pull_image golang 1.20
}

@test "[new] existing pull image index" {
    helper_pull_image_index busybox latest
}

@test "[new] existing pull oras artifact" {
    helper_pull_oras_artifact hello-artifact v2
}

@test "[new] push image" {
    helper_assert_catalog_has_repo golang
    helper_push_image golang 1.20 oci:${TEST_DATA_DIR}/golang:1.20
    helper_push_image alpine 3.17.3 docker://ghcr.io/project-zot/test-images/alpine:3.17.3
    helper_assert_catalog_has_repo golang
    helper_assert_catalog_has_repo alpine
    helper_assert_repo_has_tag golang 1.20
}

@test "[new] pull image" {
    helper_pull_image golang 1.20
}

@test "[new] push image index" {
    helper_push_image_index docker://public.ecr.aws/docker/library/busybox:latest busybox latest
}

@test "[new] pull image index" {
    helper_pull_image_index busybox latest
}

@test "[new] delete image index" {
    helper_delete_manifest busybox latest
}

@test "[new] push oras artifact" {
    helper_push_oras_artifact hello-artifact v2
}

@test "[new] pull oras artifact" {
    helper_pull_oras_artifact hello-artifact v2
}

@test "[new] attach oras artifacts" {
    helper_attach_oras_artifacts golang 1.20
}

@test "[new] discover oras artifacts" {
    helper_discover_oras_artifacts golang 1.20 4
}

@test "[new] add and list tags using oras" {
    helper_add_and_list_tags_using_oras
}

@test "[new] push helm chart" {
    helper_push_helm_chart
}

@test "[new] pull helm chart" {
    helper_pull_helm_chart
}

@test "[new] push image with regclient" {
    helper_push_image_with_regclient "ocidir://${TEST_DATA_DIR}/golang:1.20" test-regclient
}

@test "[new] pull image with regclient" {
    helper_pull_image_with_regclient test-regclient "ocidir://${TEST_DATA_DIR}/golang:1.20"
}

@test "[new] list repositories with regclient" {
    helper_list_repositories_with_regclient_pagination 4 busybox golang test-regclient "0:alpine" "-1:busybox"
}

@test "[new] list image tags with regclient" {
    helper_list_image_tags_with_regclient test-regclient
}

@test "[new] push manifest with regclient" {
    helper_push_manifest_with_regclient test-regclient 1.0.0
}

@test "[new] pull manifest with regclient" {
    helper_pull_manifest_with_regclient test-regclient
}

@test "[new] pull manifest with docker client" {
    helper_pull_manifest_with_docker_client test-regclient
}

@test "[new] pull manifest with crictl" {
    helper_pull_manifest_with_crictl test-regclient
}

@test "[new] push OCI artifact with regclient" {
    helper_push_oci_artifact_with_regclient artifact:demo
}

@test "[new] pull OCI artifact with regclient" {
    helper_pull_oci_artifact_with_regclient artifact:demo "this is an artifact"
}

@test "[new] push OCI artifact references with regclient" {
    helper_push_oci_artifact_references_with_regclient 1
}

@test "[new] pull OCI artifact references with regclient" {
    helper_pull_oci_artifact_references_with_regclient 1
}

@test "[new] build docker image and verify docker push and pull fail" {
    helper_build_docker_image_push_and_pull
}
