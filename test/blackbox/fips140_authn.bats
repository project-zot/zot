load helpers_zot
load helpers_pushpull_authn
load ../port_helper

PUSHPULL_AUTHN_FIPS_MODE=1

function setup_file() {
    authn_setup_file
}

function teardown() {
    authn_teardown
}

function teardown_file() {
    authn_teardown_file
}

@test "push image with bcrypt auth (should fail in FIPS mode)" {
    helper_authn_verify_auth_and_push "${AUTH_USER}" "${AUTH_PASS}" bcrypt false
}

@test "push image with SHA256 auth (should succeed)" {
    helper_authn_verify_auth_and_push "${AUTH_USER2}" "${AUTH_PASS2}" sha256 true
}

@test "push image with SHA512 auth (should succeed)" {
    helper_authn_verify_auth_and_push "${AUTH_USER3}" "${AUTH_PASS3}" sha512 true
}

@test "push image with SHA256 auth with 0 rounds (should succeed)" {
    helper_authn_verify_auth_and_push "${AUTH_USER4}" "${AUTH_PASS4}" sha256-0rounds true
}

@test "push image with SHA512 auth with 0 rounds (should succeed)" {
    helper_authn_verify_auth_and_push "${AUTH_USER5}" "${AUTH_PASS5}" sha512-0rounds true
}

@test "pull image with SHA256 auth" {
    helper_authn_pull_image_with_auth "${AUTH_USER2}" "${AUTH_PASS2}" test-sha256 sha256-pulled
}

@test "pull image with SHA512 auth" {
    helper_authn_pull_image_with_auth "${AUTH_USER3}" "${AUTH_PASS3}" test-sha512 sha512-pulled
}

@test "pull image with SHA256 auth with 0 rounds" {
    helper_authn_pull_image_with_auth "${AUTH_USER4}" "${AUTH_PASS4}" test-sha256-0rounds sha256-0rounds-pulled
}

@test "pull image with SHA512 auth with 0 rounds" {
    helper_authn_pull_image_with_auth "${AUTH_USER5}" "${AUTH_PASS5}" test-sha512-0rounds sha512-0rounds-pulled
}

@test "push OCI artifact with SHA256 auth" {
    helper_authn_push_oci_artifact_with_auth "${AUTH_USER2}" "${AUTH_PASS2}" \
        artifact-sha256:demo "this is an artifact with SHA256"
}

@test "push OCI artifact with SHA512 auth" {
    helper_authn_push_oci_artifact_with_auth "${AUTH_USER3}" "${AUTH_PASS3}" \
        artifact-sha512:demo "this is an artifact with SHA512"
}

@test "push OCI artifact with SHA256 auth with 0 rounds" {
    helper_authn_push_oci_artifact_with_auth "${AUTH_USER4}" "${AUTH_PASS4}" \
        artifact-sha256-0rounds:demo "this is an artifact with SHA256 and 0 rounds"
}

@test "push OCI artifact with SHA512 auth with 0 rounds" {
    helper_authn_push_oci_artifact_with_auth "${AUTH_USER5}" "${AUTH_PASS5}" \
        artifact-sha512-0rounds:demo "this is an artifact with SHA512 and 0 rounds"
}

@test "pull OCI artifact with SHA256 auth" {
    helper_authn_pull_oci_artifact_with_auth "${AUTH_USER2}" "${AUTH_PASS2}" \
        artifact-sha256:demo "this is an artifact with SHA256"
}

@test "pull OCI artifact with SHA512 auth" {
    helper_authn_pull_oci_artifact_with_auth "${AUTH_USER3}" "${AUTH_PASS3}" \
        artifact-sha512:demo "this is an artifact with SHA512"
}

@test "pull OCI artifact with SHA256 auth with 0 rounds" {
    helper_authn_pull_oci_artifact_with_auth "${AUTH_USER4}" "${AUTH_PASS4}" \
        artifact-sha256-0rounds:demo "this is an artifact with SHA256 and 0 rounds"
}

@test "pull OCI artifact with SHA512 auth with 0 rounds" {
    helper_authn_pull_oci_artifact_with_auth "${AUTH_USER5}" "${AUTH_PASS5}" \
        artifact-sha512-0rounds:demo "this is an artifact with SHA512 and 0 rounds"
}

@test "push OCI artifact references with regclient" {
    helper_authn_push_oci_artifact_references_with_auth
}

@test "list OCI artifact references with regclient" {
    helper_authn_list_oci_artifact_references_with_auth
}

@test "ML artifacts" {
    helper_authn_ml_artifacts_with_auth
}
