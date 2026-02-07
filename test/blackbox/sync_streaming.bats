# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"

# This test suite verifies the behavior of zot when streaming is enabled.

load helpers_zot
load helpers_wait
load ../port_helper

function verify_prerequisites() {
    local ok=0
    for cmd in curl jq skopeo; do
        if ! command -v "${cmd}" &>/dev/null; then
            echo "you need to install ${cmd} as a prerequisite to running the tests" >&3
            ok=1
        fi
    done

    return "${ok}"
}

# delete_repo_from_zot <port> <repo> <tag> <root>
#
# Deletes a manifest by tag from the registry at <port>, then removes the
# repo directory from the local storage root so that a subsequent on-demand
# sync fetch is triggered unconditionally (no stale blobs remain in cache).
function delete_repo_from_zot() {
    local port="${1}"
    local repo="${2}"
    local tag="${3}"
    local root="${4}"

    local digest
    digest=$(curl -sI "http://127.0.0.1:${port}/v2/${repo}/manifests/${tag}" \
        | grep -i docker-content-digest \
        | tr -d '\r' \
        | awk '{print $2}')

    curl -s -X DELETE "http://127.0.0.1:${port}/v2/${repo}/manifests/${digest}" >/dev/null

    # delete blobs from disk
    rm -rf "${root}/${repo}/blobs"
}

# verify_platforms_count_and_presence <path> <expected_platform_count>
#
# Uses "skopeo inspect --raw" on <path>, asserts the manifest list
# contains exactly <expected_platform_count> entries.
function verify_platforms_count() {
    local path="${1}"
    local expected_count="${2}"

    # Fetch the raw manifest list from the registry
    run skopeo inspect --tls-verify=false --raw "${path}"
    [ "$status" -eq 0 ]
    local raw_manifest="${lines[-1]}"

    # Assert the total platform count matches expectations
    local platform_count
    platform_count=$(echo "${raw_manifest}" | jq '.manifests | length')
    [ "${platform_count}" -eq "${expected_count}" ]
}

function setup_file() {
    # Sets a timeout so that a stalled test can fail and print logs
    export BATS_TEST_TIMEOUT=240

    if ! verify_prerequisites; then
        exit 1
    fi

    local upstream_root="${BATS_FILE_TMPDIR}/zot-upstream"
    local test_root="${BATS_FILE_TMPDIR}/zot-test"
    mkdir -p "${upstream_root}" "${test_root}"

    echo "${test_root}" > "${BATS_FILE_TMPDIR}/test_root"

    local upstream_port
    upstream_port=$(get_free_port_for_service "zot_upstream")
    echo "${upstream_port}" > "${BATS_FILE_TMPDIR}/zot.upstream.port"

    local test_port
    test_port=$(get_free_port_for_service "zot_test")
    echo "${test_port}" > "${BATS_FILE_TMPDIR}/zot.test.port"

    # Upstream config
    local upstream_config="${BATS_FILE_TMPDIR}/zot_upstream_config.json"
    cat > "${upstream_config}" <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "dedupe": false,
        "rootDirectory": "${upstream_root}"
    },
    "http": {
        "address": "127.0.0.1",
        "port": "${upstream_port}"
    },
    "log": {
        "level": "debug",
        "output": "${upstream_root}/zot.log"
    }
}
EOF

    # Test zot config
    local test_config="${BATS_FILE_TMPDIR}/zot_test_config.json"
    cat > "${test_config}" <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${test_root}"
    },
    "http": {
        "address": "127.0.0.1",
        "port": "${test_port}"
    },
    "log": {
        "level": "debug",
        "output": "${test_root}/zot.log"
    },
    "extensions": {
        "sync": {
            "enable": true,
            "registries": [
                {
                    "urls": [
                        "http://localhost:${upstream_port}"
                    ],
                    "onDemand": true,
                    "stream": true,
                    "tlsVerify": false
                }
            ]
        }
    }
}
EOF

    #Start upstream
    local zot_bin_name="zot-${OS}-${ARCH}-minimal"
    local upstream_bin="${BATS_FILE_TMPDIR}/${zot_bin_name}"
    if [ ! -f "${upstream_bin}" ]; then
        if ! curl -f -L -o "${upstream_bin}" \
                "https://github.com/project-zot/zot/releases/download/v2.1.17/${zot_bin_name}"; then
            echo "ERROR: failed to download upstream zot release binary" >&2
            exit 1
        fi
        chmod +x "${upstream_bin}"
    fi

    "${upstream_bin}" serve "${upstream_config}" &
    local upstream_pid=$!
    echo "${upstream_pid}" > "${BATS_FILE_TMPDIR}/zot.upstream.pid"
    echo -n "${upstream_pid} " >> "${BATS_FILE_TMPDIR}/zot.pid"
    echo "wait for upstream zot to be reachable..." >&3
    wait_zot_reachable "${upstream_port}"
    echo "upstream zot is reachable" >&3

    # Start zot server under test
    echo "starting zot server under test..." >&3
    zot_serve "${ZOT_PATH}" "${test_config}"
    wait_zot_reachable "${test_port}"
    echo "test zot is reachable" >&3

    # Download the test image to the shared test-data directory
    # ollama/ollama:rocm is a ~1GB image
    # image.
    skopeo copy \
        "docker://docker.io/ollama/ollama:rocm" \
        "oci:${TEST_DATA_DIR}/ollama:rocm"

    # Download the multi-arch zot image to the shared test-data directory
    # ghcr.io/project-zot/zot:v2.1.18 contains 4 platforms:
    # linux/amd64, linux/arm64 (v8), freebsd/amd64, freebsd/arm64
    skopeo copy --multi-arch=all \
        "docker://ghcr.io/project-zot/zot:v2.1.18" \
        "oci:${TEST_DATA_DIR}/zot:v2.1.18"

    # Download the multi-arch debian image to the shared test-data directory
    # docker.io/debian:trixie contains 16 platforms
    skopeo copy --multi-arch=all \
        "docker://docker.io/debian:trixie" \
        "oci:${TEST_DATA_DIR}/debian:trixie"
}

function teardown_file() {
    zot_stop_all
    local test_root
    test_root=$(cat "${BATS_FILE_TMPDIR}/test_root" 2>/dev/null || echo "")

    echo "=== upstream zot log ===" >&3
    cat "${BATS_FILE_TMPDIR}/zot-upstream/zot.log" >&3 || true

    echo "=== test zot log ===" >&3
    [ -n "${test_root}" ] && cat "${test_root}/zot.log" >&3 || true
}

@test "pull non-existent image returns NAME_UNKNOWN error" {
    local test_port
    test_port=$(cat "${BATS_FILE_TMPDIR}/zot.test.port")

    run curl -s "http://127.0.0.1:${test_port}/v2/nonexistent/manifests/latest"
    [ "$status" -eq 0 ]
    [ "$(echo "${lines[-1]}" | jq -r '.errors[0].code')" = "NAME_UNKNOWN" ]
}

@test "push image to upstream" {
    local upstream_port
    upstream_port=$(cat "${BATS_FILE_TMPDIR}/zot.upstream.port")

    run skopeo copy --dest-tls-verify=false \
        "oci:${TEST_DATA_DIR}/ollama:rocm" \
        "docker://127.0.0.1:${upstream_port}/ollama/ollama:rocm"
    [ "$status" -eq 0 ]

    # sleep for a bit to allow commit
    sleep 3

    run curl -s "http://127.0.0.1:${upstream_port}/v2/ollama/ollama/tags/list"
    [ "$status" -eq 0 ]
    [ "$(echo "${lines[-1]}" | jq -r '.tags[]')" = "rocm" ]
}

@test "concurrent pulls of image through streaming sync both succeed" {
    local test_port
    test_port=$(cat "${BATS_FILE_TMPDIR}/zot.test.port")
    local pull_dir1="${BATS_FILE_TMPDIR}/pull1"
    local pull_dir2="${BATS_FILE_TMPDIR}/pull2"
    mkdir -p "${pull_dir1}" "${pull_dir2}"

    # Launch both pulls in parallel
    skopeo --debug copy --src-tls-verify=false \
        "docker://127.0.0.1:${test_port}/ollama/ollama:rocm" \
        "oci:${pull_dir1}/ollama:rocm" >"${BATS_FILE_TMPDIR}/concur_pull_1.out" 2>&1 &
    local pid1=$!

    sleep 1

    skopeo --debug copy --src-tls-verify=false \
        "docker://127.0.0.1:${test_port}/ollama/ollama:rocm" \
        "oci:${pull_dir2}/ollama:rocm" >"${BATS_FILE_TMPDIR}/concur_pull_2.out" 2>&1 &
    local pid2=$!

    wait "${pid1}"
    local status1=$?
    wait "${pid2}"
    local status2=$?

    [ "${status1}" -eq 0 ]
    [ "${status2}" -eq 0 ]
}

@test "delete image from zot after first concurrent pull" {
    local test_port
    test_port=$(cat "${BATS_FILE_TMPDIR}/zot.test.port")
    local test_root
    test_root=$(cat "${BATS_FILE_TMPDIR}/test_root")
    local index_json="${test_root}/ollama/ollama/index.json"

    # Wait for the image to be fully committed to storage.
    sleep 30

    # Confirm the image is present on the filesystem before deleting.
    # Can't use curl here — an HTTP request would re-trigger on-demand sync.
    run jq '(.manifests // []) | map(select(.annotations["org.opencontainers.image.ref.name"] == "rocm")) | length' \
        "${index_json}"
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" -gt 0 ]

    delete_repo_from_zot "${test_port}" "ollama/ollama" "rocm" "${test_root}"

    sleep 2

    # Confirm the manifest is absent from the local OCI index after deletion.
    # Again, avoid curl to prevent on-demand re-sync from the upstream.
    run jq '(.manifests // []) | map(select(.annotations["org.opencontainers.image.ref.name"] == "rocm")) | length' \
        "${index_json}"
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" -eq 0 ]
}

@test "concurrent pulls - one terminated early while the other succeeds" {
    local test_port
    test_port=$(cat "${BATS_FILE_TMPDIR}/zot.test.port")
    local pull_dir1="${BATS_FILE_TMPDIR}/pull3"
    local pull_dir2="${BATS_FILE_TMPDIR}/pull4"
    mkdir -p "${pull_dir1}" "${pull_dir2}"

    # Start both pulls in parallel.
    skopeo --debug copy --src-tls-verify=false \
        "docker://127.0.0.1:${test_port}/ollama/ollama:rocm" \
        "oci:${pull_dir1}/ollama:rocm" >"${BATS_FILE_TMPDIR}/concur_pull_3.out" 2>&1 &
    local pid1=$!

    sleep 1

    skopeo --debug copy --src-tls-verify=false \
        "docker://127.0.0.1:${test_port}/ollama/ollama:rocm" \
        "oci:${pull_dir2}/ollama:rocm" >"${BATS_FILE_TMPDIR}/concur_pull_4.out" 2>&1 &
    local pid2=$!

    # Allow streaming to begin, then terminate the first client.
    sleep 2

    kill "${pid1}" 2>/dev/null || true
    for i in {1..3}; do
        kill -0 "${pid1}" 2>/dev/null || break
        sleep 1
    done
    kill -0 "${pid1}" 2>/dev/null && kill -9 "${pid1}"
    wait "${pid1}" 2>/dev/null || true

    # The second pull must complete successfully regardless.
    wait "${pid2}"
    local status_pid2=$?
    [ "${status_pid2}" -eq 0 ]
}

@test "delete image from zot after client interrupted pull" {
    local test_port
    test_port=$(cat "${BATS_FILE_TMPDIR}/zot.test.port")
    local test_root
    test_root=$(cat "${BATS_FILE_TMPDIR}/test_root")
    local index_json="${test_root}/ollama/ollama/index.json"

    # Wait for the image to be fully committed to storage.
    sleep 30

    # Confirm the image is present on the filesystem before deleting.
    # Can't use curl here — an HTTP request would re-trigger on-demand sync.
    run jq '(.manifests // []) | map(select(.annotations["org.opencontainers.image.ref.name"] == "rocm")) | length' \
        "${index_json}"
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" -gt 0 ]

    delete_repo_from_zot "${test_port}" "ollama/ollama" "rocm" "${test_root}"

    sleep 2

    # Confirm the manifest is absent from the local OCI index after deletion.
    # Again, avoid curl to prevent on-demand re-sync from the upstream.
    run jq '(.manifests // []) | map(select(.annotations["org.opencontainers.image.ref.name"] == "rocm")) | length' \
        "${index_json}"
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" -eq 0 ]
}

@test "push multi-arch test images to upstream" {
    local upstream_port
    upstream_port=$(cat "${BATS_FILE_TMPDIR}/zot.upstream.port")

    run skopeo copy --dest-tls-verify=false --multi-arch=all \
        "oci:${TEST_DATA_DIR}/zot:v2.1.18" \
        "docker://127.0.0.1:${upstream_port}/project-zot/zot:v2.1.18"
    [ "$status" -eq 0 ]

    # sleep for a bit to allow commit
    sleep 3

    run curl -s "http://127.0.0.1:${upstream_port}/v2/project-zot/zot/tags/list"
    [ "$status" -eq 0 ]
    [ "$(echo "${lines[-1]}" | jq -r '.tags[]')" = "v2.1.18" ]

    verify_platforms_count "docker://127.0.0.1:${upstream_port}/project-zot/zot:v2.1.18" 4

    run skopeo copy --dest-tls-verify=false --multi-arch=all \
        "oci:${TEST_DATA_DIR}/debian:trixie" \
        "docker://127.0.0.1:${upstream_port}/debian:trixie"
    [ "$status" -eq 0 ]

    # sleep for a bit to allow commit
    sleep 3

    run curl -s "http://127.0.0.1:${upstream_port}/v2/debian/tags/list"
    [ "$status" -eq 0 ]
    [ "$(echo "${lines[-1]}" | jq -r '.tags[]')" = "trixie" ]

    verify_platforms_count "docker://127.0.0.1:${upstream_port}/debian:trixie" 16
}

@test "skopeo pulls all platforms of multi-arch zot image through streaming sync" {
    local test_port
    test_port=$(cat "${BATS_FILE_TMPDIR}/zot.test.port")
    local pull_dir="${BATS_FILE_TMPDIR}/zot-multi-arch-all"
    mkdir -p "${pull_dir}"

    # Pull all platforms from the multi-arch manifest list
    run skopeo --debug copy --src-tls-verify=false --multi-arch=all \
        "docker://127.0.0.1:${test_port}/project-zot/zot:v2.1.18" \
        "oci:${pull_dir}"
    [ "$status" -eq 0 ]

    verify_platforms_count "oci:${pull_dir}" 4
}

@test "skopeo pulls all platforms of multi-arch debian image through streaming sync" {
    local test_port
    test_port=$(cat "${BATS_FILE_TMPDIR}/zot.test.port")
    local pull_dir="${BATS_FILE_TMPDIR}/debian-multi-arch-all"
    mkdir -p "${pull_dir}"

    # Pull all platforms from the multi-arch manifest list
    run skopeo --debug copy --src-tls-verify=false --multi-arch=all \
        "docker://127.0.0.1:${test_port}/debian:trixie" \
        "oci:${pull_dir}"
    [ "$status" -eq 0 ]

    verify_platforms_count "oci:${pull_dir}" 16
}

@test "skopeo pulls single platform from zot multi-arch image through streaming sync" {
    local test_port
    test_port=$(cat "${BATS_FILE_TMPDIR}/zot.test.port")
    local pull_dir="${BATS_FILE_TMPDIR}/zot-multi-arch-single"
    mkdir -p "${pull_dir}"

    # Pull only the linux/amd64 platform, excluding all others
    run skopeo copy --src-tls-verify=false \
        "docker://127.0.0.1:${test_port}/project-zot/zot:v2.1.18" \
        "oci:${pull_dir}" \
        --override-os linux \
        --override-arch amd64
    [ "$status" -eq 0 ]

   run skopeo inspect --tls-verify=false --raw "oci:${pull_dir}"
   [ "$status" -eq 0 ]
   local raw_manifest="${lines[-1]}"

   # Assert the output is a manifest list (OCI image index or Docker manifest list)
   local media_type
   media_type=$(echo "${raw_manifest}" | jq -r '.mediaType // empty')
   [ "$media_type" = "application/vnd.oci.image.manifest.v1+json" ]
}

@test "pull fails with error when upstream is killed during streaming" {
    local test_port
    test_port=$(cat "${BATS_FILE_TMPDIR}/zot.test.port")
    local upstream_pid
    upstream_pid=$(cat "${BATS_FILE_TMPDIR}/zot.upstream.pid")
    local pull_dir="${BATS_FILE_TMPDIR}/pull5"
    mkdir -p "${pull_dir}"

    # Start the pull in the background
    skopeo --debug copy --src-tls-verify=false \
        "docker://127.0.0.1:${test_port}/ollama/ollama:rocm" \
        "oci:${pull_dir}/ollama:rocm" > "${BATS_FILE_TMPDIR}/pull_5.out" 2>&1 &
    local copier_pid=$!

    sleep 1

    kill "${upstream_pid}" 2>/dev/null || true

    # Wait for copier to exit; it must fail because the upstream is gone.
    run wait "${copier_pid}"
    [ "$status" -ne 0 ]
}

@test "pull succeeds after upstream is restarted" {
    local upstream_port
    upstream_port=$(cat "${BATS_FILE_TMPDIR}/zot.upstream.port")
    local test_port
    test_port=$(cat "${BATS_FILE_TMPDIR}/zot.test.port")

    # Restart the upstream with the same binary and config used in setup_file.
    local upstream_bin="${BATS_FILE_TMPDIR}/zot-${OS}-${ARCH}-minimal"
    local upstream_config="${BATS_FILE_TMPDIR}/zot_upstream_config.json"

    "${upstream_bin}" serve "${upstream_config}" &
    local new_upstream_pid=$!
    echo -n "${new_upstream_pid} " >> "${BATS_FILE_TMPDIR}/zot.pid"
    echo "${new_upstream_pid}" > "${BATS_FILE_TMPDIR}/zot.upstream.pid"
    wait_zot_reachable "${upstream_port}"

    local pull_dir="${BATS_FILE_TMPDIR}/pull6"
    mkdir -p "${pull_dir}"

    run skopeo --debug copy --src-tls-verify=false \
        "docker://127.0.0.1:${test_port}/ollama/ollama:rocm" \
        "oci:${pull_dir}/ollama:rocm" > "${BATS_FILE_TMPDIR}/pull_6.out" 2>&1
    [ "$status" -eq 0 ]
}
