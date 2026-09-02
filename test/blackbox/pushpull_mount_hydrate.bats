# hydrateBlobOnRead rematerialization authz (HEAD / ranged GET).
# Mount POST coverage lives in pushpull_mount.bats (explicit mounts are unaffected
# by hydrateBlobOnRead); this suite uses a separate zot with hydrate enabled so
# HEAD absence checks in the mount suite stay meaningful.

load helpers_zot
load helpers_pushpull_mount
load ../port_helper

function setup_file() {
    mount_setup_file true
}

function teardown() {
    mount_teardown
}

function teardown_file() {
    mount_teardown_file
}

@test "curl HEAD hydrate denied without source read returns 404" {
    local digest
    digest=$(mount_get_layer_digest)

    mount_curl_blob_head "${MOUNT_USER2}" "${MOUNT_PASS2}" \
        "${MOUNT_REPO2_HYDRATE_HEAD}" "${digest}"
    [ "${status}" -eq 0 ]
    [ "${output}" = "404" ]
}

@test "curl ranged GET hydrate denied without source read returns 404" {
    local digest
    digest=$(mount_get_layer_digest)

    mount_curl_blob_range_get "${MOUNT_USER2}" "${MOUNT_PASS2}" \
        "${MOUNT_REPO2_HYDRATE_RANGE}" "${digest}"
    [ "${status}" -eq 0 ]
    [ "${output}" = "404" ]
}

@test "regctl blob head hydrate denied without source read fails" {
    local digest zot_port
    digest=$(mount_get_layer_digest)
    zot_port=$(get_zot_port)

    mount_regctl_login "${MOUNT_USER2}" "${MOUNT_PASS2}"
    run "$(mount_get_regctl)" $(mount_regctl_host_flags) blob head \
        "localhost:${zot_port}/${MOUNT_REPO2_HYDRATE_HEAD}" "${digest}"
    [ "${status}" -ne 0 ]
}

@test "curl HEAD hydrate allowed with source read returns 200" {
    local digest zot_port
    digest=$(mount_get_layer_digest)
    zot_port=$(get_zot_port)

    mount_regctl_login "${MOUNT_USER1}" "${MOUNT_PASS1}"
    mount_curl_blob_head "${MOUNT_USER1}" "${MOUNT_PASS1}" \
        "${MOUNT_REPO1_HYDRATE_HEAD}" "${digest}"
    [ "${status}" -eq 0 ]
    [ "${output}" = "200" ]

    run "$(mount_get_regctl)" $(mount_regctl_host_flags) blob head \
        "localhost:${zot_port}/${MOUNT_REPO1_HYDRATE_HEAD}" "${digest}"
    [ "${status}" -eq 0 ]
}

@test "curl ranged GET hydrate allowed with source read returns 206" {
    local digest
    digest=$(mount_get_layer_digest)

    mount_curl_blob_range_get "${MOUNT_USER1}" "${MOUNT_PASS1}" \
        "${MOUNT_REPO1_HYDRATE_RANGE}" "${digest}"
    [ "${status}" -eq 0 ]
    [ "${output}" = "206" ]
}
