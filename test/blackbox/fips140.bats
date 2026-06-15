# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_pushpull
load ../port_helper

PUSHPULL_FIPS_MODE=1

function setup_file() {
    pushpull_setup_file
}

function teardown() {
    pushpull_teardown
}

function teardown_file() {
    pushpull_teardown_file
}

@test "push image" {
    helper_push_image golang 1.20 oci:${TEST_DATA_DIR}/golang:1.20
}

@test "pull image" {
    helper_pull_image golang 1.20
}

@test "push image index" {
    helper_push_image_index docker://public.ecr.aws/docker/library/busybox:latest busybox latest
}

@test "pull image index" {
    helper_pull_image_index busybox latest
}

@test "delete image index" {
    helper_delete_manifest busybox latest
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
    helper_push_image_with_regclient "ocidir://${TEST_DATA_DIR}/golang:1.20" test-regclient
}

@test "pull image with regclient" {
    helper_pull_image_with_regclient test-regclient "ocidir://${TEST_DATA_DIR}/golang:1.20"
}

@test "list repositories with regclient" {
    helper_list_repositories_with_regclient_pagination 2 busybox golang test-regclient "-2:busybox" "-1:golang"
}

@test "list image tags with regclient" {
    helper_list_image_tags_with_regclient test-regclient
}

@test "push manifest with regclient" {
    helper_push_manifest_with_regclient test-regclient 1.0.0
}

@test "pull manifest with regclient" {
    helper_pull_manifest_with_regclient test-regclient
}

@test "pull manifest with docker client" {
    helper_pull_manifest_with_docker_client test-regclient
}

@test "pull manifest with crictl" {
    helper_pull_manifest_with_crictl test-regclient
}

@test "push OCI artifact with regclient" {
    helper_push_oci_artifact_with_regclient artifact:demo
}

@test "pull OCI artifact with regclient" {
    helper_pull_oci_artifact_with_regclient artifact:demo "this is an artifact"
}

@test "push OCI artifact references with regclient" {
    helper_push_oci_artifact_references_with_regclient 0
}

@test "pull OCI artifact references with regclient" {
    helper_pull_oci_artifact_references_with_regclient 1
}

@test "build docker image and verify docker push and pull fail" {
    helper_build_docker_image_push_and_pull
}
