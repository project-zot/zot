load helpers_zot
load helpers_pushpull_mount
load ../port_helper

function setup_file() {
    mount_setup_file
}

function teardown() {
    mount_teardown
}

function teardown_file() {
    mount_teardown_file
}

@test "curl mount denied without source read returns 202" {
    local digest
    digest=$(mount_get_layer_digest)

    mount_curl_blob_upload "${MOUNT_USER2}" "${MOUNT_PASS2}" "${MOUNT_REPO2}" "${digest}"
    [ "${status}" -eq 0 ]
    [ "${output}" = "202" ]
}

@test "curl mount denied with from returns 202" {
    local digest
    digest=$(mount_get_layer_digest)

    mount_curl_blob_upload "${MOUNT_USER2}" "${MOUNT_PASS2}" "${MOUNT_REPO2_OTHER}" \
        "${digest}" "${MOUNT_REPO1}"
    [ "${status}" -eq 0 ]
    [ "${output}" = "202" ]
}

# hydrateBlobOnRead defaults to false: authorized callers still do not rematerialize
# via HEAD / ranged GET (repo-local StatBlob only). Contrast pushpull_mount_hydrate.bats.
@test "curl HEAD with hydrate off does not rematerialize returns 404" {
    local digest
    digest=$(mount_get_layer_digest)

    mount_curl_blob_head "${MOUNT_USER1}" "${MOUNT_PASS1}" \
        "${MOUNT_REPO1_NOHYDRATE_HEAD}" "${digest}"
    [ "${status}" -eq 0 ]
    [ "${output}" = "404" ]
}

@test "curl ranged GET with hydrate off does not rematerialize returns 404" {
    local digest
    digest=$(mount_get_layer_digest)

    mount_curl_blob_range_get "${MOUNT_USER1}" "${MOUNT_PASS1}" \
        "${MOUNT_REPO1_NOHYDRATE_RANGE}" "${digest}"
    [ "${status}" -eq 0 ]
    [ "${output}" = "404" ]
}

@test "regctl blob head with hydrate off does not rematerialize fails" {
    local digest zot_port
    digest=$(mount_get_layer_digest)
    zot_port=$(get_zot_port)

    mount_regctl_login "${MOUNT_USER1}" "${MOUNT_PASS1}"
    run "$(mount_get_regctl)" $(mount_regctl_host_flags) blob head \
        "localhost:${zot_port}/${MOUNT_REPO1_NOHYDRATE_HEAD}" "${digest}"
    [ "${status}" -ne 0 ]
}

@test "regctl blob copy mount denied without source read returns 202" {
    local digest log_file regctl status
    digest=$(mount_get_layer_digest)
    log_file="${BATS_FILE_TMPDIR}/regctl-blob-copy-denied.log"
    regctl="$(mount_get_regctl)"

    mount_regctl_login "${MOUNT_USER2}" "${MOUNT_PASS2}"
    set +e
    "${regctl}" $(mount_regctl_host_flags) blob copy \
        "localhost:$(get_zot_port)/${MOUNT_REPO1}" \
        "localhost:$(get_zot_port)/${MOUNT_REPO2_OTHER}" \
        "${digest}" -v trace 2>"${log_file}"
    status=$?
    set -e
    [ "${status}" -eq 1 ]

    grep -Fq "202 Accepted" "${log_file}"
}

@test "regctl blob copy with source read succeeds" {
    local digest zot_port
    digest=$(mount_get_layer_digest)
    zot_port=$(get_zot_port)

    mount_regctl_login "${MOUNT_USER1}" "${MOUNT_PASS1}"
    run "$(mount_get_regctl)" $(mount_regctl_host_flags) blob copy \
        "localhost:${zot_port}/${MOUNT_REPO1}" \
        "localhost:${zot_port}/${MOUNT_REPO1_SECOND}" \
        "${digest}"
    [ "${status}" -eq 0 ]

    run "$(mount_get_regctl)" $(mount_regctl_host_flags) blob head \
        "localhost:${zot_port}/${MOUNT_REPO1_SECOND}" "${digest}"
    [ "${status}" -eq 0 ]
}

@test "curl mount allowed with source read returns 201" {
    local digest zot_port
    digest=$(mount_get_layer_digest)
    zot_port=$(get_zot_port)

    mount_regctl_login "${MOUNT_USER1}" "${MOUNT_PASS1}"
    run "$(mount_get_regctl)" $(mount_regctl_host_flags) blob head \
        "localhost:${zot_port}/${MOUNT_REPO1_CURL}" "${digest}"
    [ "${status}" -ne 0 ]

    mount_curl_blob_upload "${MOUNT_USER1}" "${MOUNT_PASS1}" "${MOUNT_REPO1_CURL}" \
        "${digest}" "${MOUNT_REPO1}"
    [ "${status}" -eq 0 ]
    [ "${output}" = "201" ]

    run "$(mount_get_regctl)" $(mount_regctl_host_flags) blob head \
        "localhost:${zot_port}/${MOUNT_REPO1_CURL}" "${digest}"
    [ "${status}" -eq 0 ]
}

@test "curl cross-repo mount allowed after blob is readable returns 201" {
    local digest zot_port
    digest=$(mount_get_layer_digest)
    zot_port=$(get_zot_port)

    mount_regctl_login "${MOUNT_USER2}" "${MOUNT_PASS2}"
    run "$(mount_get_regctl)" $(mount_regctl_host_flags) image copy "ocidir://${TEST_DATA_DIR}/busybox:1.36" \
        "localhost:${zot_port}/${MOUNT_REPO2}:1.36"
    [ "${status}" -eq 0 ]

    run "$(mount_get_regctl)" $(mount_regctl_host_flags) blob head \
        "localhost:${zot_port}/${MOUNT_REPO2_OTHER}" "${digest}"
    [ "${status}" -ne 0 ]

    mount_curl_blob_upload "${MOUNT_USER2}" "${MOUNT_PASS2}" "${MOUNT_REPO2_OTHER}" \
        "${digest}" "${MOUNT_REPO2}"
    [ "${status}" -eq 0 ]
    [ "${output}" = "201" ]
}
