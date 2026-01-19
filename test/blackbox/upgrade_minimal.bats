# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_upgrade
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
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    mkdir -p ${zot_root_dir}
    mkdir -p ${oci_data_dir}
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
        "output": "${BATS_FILE_TMPDIR}/zot.log"
    }
}
JSON
    git -C ${BATS_FILE_TMPDIR} clone https://github.com/project-zot/helm-charts.git
    zot_rel_min_serve ${zot_config_file}
    wait_zot_reachable ${zot_port}
}

@test "[release] push image" {
    test_release_push_image
}

@test "[release] pull image" {
    test_release_pull_image
}

@test "[release] push image index" {
    test_release_push_image_index
}

@test "[release] pull image index" {
    test_release_pull_image_index
}

@test "[release] push oras artifact" {
    test_release_push_oras_artifact
}

@test "[release] pull oras artifact" {
    test_release_pull_oras_artifact
}

@test "[release] attach oras artifacts" {
    test_release_attach_oras_artifacts
}

@test "[release] discover oras artifacts" {
    test_release_discover_oras_artifacts
}

@test "[release] add and list tags using oras" {
    test_release_add_and_list_tags_using_oras
}

@test "[release] push helm chart" {
    test_release_push_helm_chart
}

@test "[release] pull helm chart" {
    test_release_pull_helm_chart
}

@test "[release] push image with regclient" {
    test_release_push_image_with_regclient
}

@test "[release] pull image with regclient" {
    test_release_pull_image_with_regclient
}

@test "[release] list repositories with regclient" {
    test_release_list_repositories_with_regclient
}

@test "[release] list image tags with regclient" {
    test_release_list_image_tags_with_regclient
}

@test "[release] push manifest with regclient" {
    test_release_push_manifest_with_regclient
}

@test "[release] pull manifest with regclient" {
    test_release_pull_manifest_with_regclient
}

@test "[release] pull manifest with docker client" {
    test_release_pull_manifest_with_docker_client
}

@test "[release] pull manifest with crictl" {
    test_release_pull_manifest_with_crictl
}

@test "[release] push OCI artifact with regclient" {
    test_release_push_oci_artifact_with_regclient
}

@test "[release] pull OCI artifact with regclient" {
    test_release_pull_oci_artifact_with_regclient
}

@test "[release] push OCI artifact references with regclient" {
    test_release_push_oci_artifact_references_with_regclient
}

@test "[release] pull OCI artifact references with regclient" {
    test_release_pull_oci_artifact_references_with_regclient
}

@test "[release] push docker image" {
    test_release_push_docker_image
}

@test "[upgrade] upgrade to new binary" {
    zot_stop_all
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    zot_serve ${ZOT_MINIMAL_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}
    sleep 60    # zot does additional initialization/verification during startup
}

# After upgrading to the new binary, expect additional artifacts (a signature
# and an sbom) that were attached

@test "[new] existing pull image" {
    test_new_existing_pull_image
}

@test "[new] existing pull image index" {
    test_new_existing_pull_image_index
}

@test "[new] existing pull oras artifact" {
    test_new_existing_pull_oras_artifact
}

@test "[new] push image" {
    test_new_push_image
}

@test "[new] pull image" {
    test_new_pull_image
}

@test "[new] push image index" {
    test_new_push_image_index
}

@test "[new] pull image index" {
    test_new_pull_image_index
}

@test "[new] push oras artifact" {
    test_new_push_oras_artifact
}

@test "[new] pull oras artifact" {
    test_new_pull_oras_artifact
}

@test "[new] attach oras artifacts" {
    test_new_attach_oras_artifacts
}

@test "[new] discover oras artifacts" {
    test_new_discover_oras_artifacts 4
}

@test "[new] add and list tags using oras" {
    test_new_add_and_list_tags_using_oras
}

@test "[new] push helm chart" {
    test_new_push_helm_chart
}

@test "[new] pull helm chart" {
    test_new_pull_helm_chart
}

@test "[new] push image with regclient" {
    test_new_push_image_with_regclient
}

@test "[new] pull image with regclient" {
    test_new_pull_image_with_regclient
}

@test "[new] list repositories with regclient" {
    test_new_list_repositories_with_regclient
}

@test "[new] list image tags with regclient" {
    test_new_list_image_tags_with_regclient
}

@test "[new] push manifest with regclient" {
    test_new_push_manifest_with_regclient
}

@test "[new] pull manifest with regclient" {
    test_new_pull_manifest_with_regclient
}

@test "[new] pull manifest with docker client" {
    test_new_pull_manifest_with_docker_client
}

@test "[new] pull manifest with crictl" {
    test_new_pull_manifest_with_crictl
}

@test "[new] push OCI artifact with regclient" {
    test_new_push_oci_artifact_with_regclient
}

@test "[new] pull OCI artifact with regclient" {
    test_new_pull_oci_artifact_with_regclient
}

@test "[new] push OCI artifact references with regclient" {
    test_new_push_oci_artifact_references_with_regclient
}

@test "[new] pull OCI artifact references with regclient" {
    test_new_pull_oci_artifact_references_with_regclient
}

@test "[new] push docker image" {
    test_new_push_docker_image
}
