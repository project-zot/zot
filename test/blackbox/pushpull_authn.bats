load helpers_zot
load helpers_pushpull_authn
load ../port_helper

PUSHPULL_AUTHN_FIPS_MODE=0

function setup_file() {
    authn_setup_file
}

function teardown() {
    authn_teardown
}

function teardown_file() {
    authn_teardown_file
}

@test "push image with regclient" {
    helper_authn_push_image_with_regclient "ocidir://${TEST_DATA_DIR}/busybox:1.36" test-regclient
}

@test "pull image with regclient" {
    helper_authn_pull_image_with_regclient test-regclient "ocidir://${TEST_DATA_DIR}/busybox:latest"
}

@test "push OCI artifact with regclient" {
    helper_authn_push_oci_artifact_with_regclient artifact:demo
}

@test "pull OCI artifact with regclient" {
    helper_authn_pull_oci_artifact_with_regclient artifact:demo "this is an artifact"
}

@test "push OCI artifact references with regclient" {
    helper_authn_push_oci_artifact_references_with_regclient
}

@test "list OCI artifact references with regclient" {
    helper_authn_list_oci_artifact_references_with_regclient
}

@test "ML artifacts" {
    helper_authn_ml_artifacts "${AUTH_USER}" "${AUTH_PASS}"
}
