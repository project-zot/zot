# Common helper functions and test utilities for upgrade tests.
# Used by upgrade.bats and upgrade_minimal.bats.

load helpers_pushpull

function teardown() {
    # conditionally printing on failure is possible from teardown but not from teardown_file
    cat "${BATS_FILE_TMPDIR}/zot.log"
}

function teardown_file() {
    zot_stop_all
}

# ==============================================================================
# RELEASE TEST FUNCTIONS
# These functions are used to test the released version of zot before upgrade.
# ==============================================================================

function test_release_push_image() {
    helper_push_image golang 1.20
}

function test_release_pull_image() {
    helper_pull_image golang 1.20
}

function test_release_push_image_index() {
    helper_push_image_index docker://public.ecr.aws/docker/library/busybox:latest busybox latest
}

function test_release_pull_image_index() {
    helper_pull_image_index busybox latest
}

function test_release_push_oras_artifact() {
    helper_push_oras_artifact hello-artifact v2
}

function test_release_pull_oras_artifact() {
    helper_pull_oras_artifact hello-artifact v2
}

function test_release_attach_oras_artifacts() {
    helper_attach_oras_artifacts golang 1.20
}

function test_release_discover_oras_artifacts() {
    helper_discover_oras_artifacts golang 1.20 2
}

function test_release_add_and_list_tags_using_oras() {
    helper_add_and_list_tags_using_oras
}

function test_release_push_helm_chart() {
    helper_push_helm_chart
}

function test_release_pull_helm_chart() {
    helper_pull_helm_chart
}

function test_release_push_image_with_regclient() {
    helper_push_image_with_regclient
}

function test_release_pull_image_with_regclient() {
    helper_pull_image_with_regclient
}

function test_release_list_repositories_with_regclient() {
    helper_list_repositories_with_regclient_pagination 2 busybox golang "-2:busybox" "-1:golang"
}

function test_release_list_image_tags_with_regclient() {
    helper_list_image_tags_with_regclient
}

function test_release_push_manifest_with_regclient() {
    helper_push_manifest_with_regclient
}

function test_release_pull_manifest_with_regclient() {
    helper_pull_manifest_with_regclient
}

function test_release_pull_manifest_with_docker_client() {
    helper_pull_manifest_with_docker_client
}

function test_release_pull_manifest_with_crictl() {
    helper_pull_manifest_with_crictl
}

function test_release_push_oci_artifact_with_regclient() {
    helper_push_oci_artifact_with_regclient
}

function test_release_pull_oci_artifact_with_regclient() {
    helper_pull_oci_artifact_with_regclient
}

function test_release_push_oci_artifact_references_with_regclient() {
    helper_push_oci_artifact_references_with_regclient 0
}

function test_release_pull_oci_artifact_references_with_regclient() {
    helper_pull_oci_artifact_references_with_regclient 1
}

function test_release_push_docker_image() {
    helper_push_docker_image
}

# ==============================================================================
# NEW (POST-UPGRADE) TEST FUNCTIONS
# These functions are used to test the new version of zot after upgrade.
# ==============================================================================

function test_new_existing_pull_image() {
    helper_pull_image golang 1.20
}

function test_new_existing_pull_image_index() {
    helper_pull_image_index busybox latest
}

function test_new_existing_pull_oras_artifact() {
    helper_pull_oras_artifact hello-artifact v2
}

function test_new_push_image() {
    helper_assert_catalog_has_repo golang
    helper_push_image golang 1.20
    helper_push_image alpine 3.17.3 docker://ghcr.io/project-zot/test-images/alpine:3.17.3
    helper_assert_catalog_has_repo golang
    helper_assert_catalog_has_repo alpine
    helper_assert_repo_has_tag golang 1.20
}

function test_new_pull_image() {
    helper_pull_image golang 1.20
}

function test_new_push_image_index() {
    helper_push_image_index docker://public.ecr.aws/docker/library/busybox:latest busybox latest
}

function test_new_pull_image_index() {
    helper_pull_image_index_and_delete busybox latest
}

function test_new_push_oras_artifact() {
    helper_push_oras_artifact hello-artifact v2
}

function test_new_pull_oras_artifact() {
    helper_pull_oras_artifact hello-artifact v2
}

function test_new_attach_oras_artifacts() {
    helper_attach_oras_artifacts golang 1.20
}

# Args: $1 = expected artifact count. Full and minimal zot can have different counts.
function test_new_discover_oras_artifacts() {
    local expected_count=${1:-4}
    helper_discover_oras_artifacts golang 1.20 "${expected_count}"
}

function test_new_add_and_list_tags_using_oras() {
    helper_add_and_list_tags_using_oras
}

function test_new_push_helm_chart() {
    helper_push_helm_chart
}

function test_new_pull_helm_chart() {
    helper_pull_helm_chart
}

function test_new_push_image_with_regclient() {
    helper_push_image_with_regclient
}

function test_new_pull_image_with_regclient() {
    helper_pull_image_with_regclient
}

function test_new_list_repositories_with_regclient() {
    helper_list_repositories_with_regclient_pagination 4 busybox golang "0:alpine" "-1:busybox"
}

function test_new_list_image_tags_with_regclient() {
    helper_list_image_tags_with_regclient
}

function test_new_push_manifest_with_regclient() {
    helper_push_manifest_with_regclient
}

function test_new_pull_manifest_with_regclient() {
    helper_pull_manifest_with_regclient
}

function test_new_pull_manifest_with_docker_client() {
    helper_pull_manifest_with_docker_client
}

function test_new_pull_manifest_with_crictl() {
    helper_pull_manifest_with_crictl
}

function test_new_push_oci_artifact_with_regclient() {
    helper_push_oci_artifact_with_regclient
}

function test_new_pull_oci_artifact_with_regclient() {
    helper_pull_oci_artifact_with_regclient
}

function test_new_push_oci_artifact_references_with_regclient() {
    helper_push_oci_artifact_references_with_regclient 1
}

function test_new_pull_oci_artifact_references_with_regclient() {
    helper_pull_oci_artifact_references_with_regclient 1
}

function test_new_push_docker_image() {
    helper_push_docker_image
}
