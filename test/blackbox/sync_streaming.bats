# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()
#
# Load coverage for streaming on-demand sync (extensions.sync.registries[].stream): many concurrent
# clients pulling a not-yet-synced tag all get correct content; concurrent pulls of different tags
# past maxConcurrentStreams fall back to the plain path instead of failing; the background sync
# still commits the image; and a multi-arch index is synced sparsely, with only the platform
# manifest the client then requests by digest being streamed.

load helpers_zot
load helpers_wait
load ../port_helper

function verify_prerequisites() {
    if ! command -v curl >/dev/null 2>&1; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if ! command -v jq >/dev/null 2>&1; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    if ! command -v openssl >/dev/null 2>&1; then
        echo "you need to install openssl as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

# Generate a self-signed certificate with the given CN/SAN (Go's TLS client requires a SAN).
function generate_self_signed_cert() {
    local cert_path=${1}
    local key_path=${2}
    local common_name=${3:-"localhost"}

    openssl req -x509 -newkey rsa:2048 -keyout "${key_path}" -out "${cert_path}" \
        -days 365 -nodes \
        -subj "/C=US/ST=Test/L=Test/O=Zot/CN=${common_name}" \
        -addext "subjectAltName=DNS:${common_name},IP:127.0.0.1"
}

function setup_file() {
    if ! verify_prerequisites; then
        exit 1
    fi

    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/test-images/busybox:1.36 oci:${TEST_DATA_DIR}/busybox:1.36

    # Size maxConcurrentStreams from the fixtures: enough to stage one image fully (config and
    # layers; the manifest gets no stream) but not both, so the different-tags test really contends
    # for the cap. skopeo inspect avoids depending on the OCI layout's on-disk naming.
    local golang_blob_count busybox_blob_count
    golang_blob_count=$(skopeo inspect --raw "oci:${TEST_DATA_DIR}/golang:1.20" |
        jq '([.config.digest] + [.layers[].digest]) | unique | length')
    busybox_blob_count=$(skopeo inspect --raw "oci:${TEST_DATA_DIR}/busybox:1.36" |
        jq '([.config.digest] + [.layers[].digest]) | unique | length')

    local zot_stream_max_concurrent_streams
    zot_stream_max_concurrent_streams=$(( golang_blob_count > busybox_blob_count ? golang_blob_count : busybox_blob_count ))

    local zot_minimal_root_dir=${BATS_FILE_TMPDIR}/zot-minimal
    local zot_minimal_config_file=${BATS_FILE_TMPDIR}/zot_minimal_config.json
    local zot_minimal_cert_file=${BATS_FILE_TMPDIR}/zot_minimal_server.cert
    local zot_minimal_key_file=${BATS_FILE_TMPDIR}/zot_minimal_server.key

    local zot_stream_root_dir=${BATS_FILE_TMPDIR}/zot-stream
    local zot_stream_config_file=${BATS_FILE_TMPDIR}/zot_stream_config.json
    local zot_stream_cert_dir=${BATS_FILE_TMPDIR}/zot-stream-certs

    local zot_stream_capped_root_dir=${BATS_FILE_TMPDIR}/zot-stream-capped
    local zot_stream_capped_config_file=${BATS_FILE_TMPDIR}/zot_stream_capped_config.json
    local zot_stream_capped_cert_dir=${BATS_FILE_TMPDIR}/zot-stream-capped-certs

    mkdir -p ${zot_minimal_root_dir}
    mkdir -p ${zot_stream_root_dir}
    mkdir -p ${zot_stream_capped_root_dir}
    mkdir -p ${zot_stream_cert_dir}
    mkdir -p ${zot_stream_capped_cert_dir}

    # Streaming requires a TLS-verified upstream: the downstream trusts this self-signed cert via
    # certDir, so verification stays on.
    generate_self_signed_cert "${zot_minimal_cert_file}" "${zot_minimal_key_file}" "localhost"
    cp "${zot_minimal_cert_file}" "${zot_stream_cert_dir}/ca.crt"
    cp "${zot_minimal_cert_file}" "${zot_stream_capped_cert_dir}/ca.crt"

    zot_minimal_port=$(get_free_port_for_service "zot_min")
    echo ${zot_minimal_port} > ${BATS_FILE_TMPDIR}/zot_min.port

    zot_stream_port=$(get_free_port_for_service "zot_stream")
    echo ${zot_stream_port} > ${BATS_FILE_TMPDIR}/zot_stream.port

    zot_stream_capped_port=$(get_free_port_for_service "zot_stream_capped")
    echo ${zot_stream_capped_port} > ${BATS_FILE_TMPDIR}/zot_stream_capped.port

    cat >${zot_minimal_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_minimal_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_minimal_port}",
        "tls": {
            "cert": "${zot_minimal_cert_file}",
            "key": "${zot_minimal_key_file}"
        }
    },
    "log": {
        "level": "debug",
        "output": "${zot_minimal_root_dir}/zot.log"
    }
}
EOF

    # One upstream tag pulled by many clients at once: exercises the shared stream and the deduped
    # background sync under real HTTP concurrency.
    cat >${zot_stream_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_stream_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_stream_port}",
        "compat": ["docker2s2"]
    },
    "log": {
        "level": "debug",
        "output": "${zot_stream_root_dir}/zot.log"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": ["https://localhost:${zot_minimal_port}"],
                    "onDemand": true,
                    "stream": true,
                    "certDir": "${zot_stream_cert_dir}",
                    "content": [{"prefix": "**"}]
                }
            ]
        }
    }
}
EOF

    # Fits one of golang:1.20/busybox:1.36 but not both (see zot_stream_max_concurrent_streams), so
    # pulls of different tags hit the cap and exercise the fallback.
    cat >${zot_stream_capped_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_stream_capped_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_stream_capped_port}",
        "compat": ["docker2s2"]
    },
    "log": {
        "level": "debug",
        "output": "${zot_stream_capped_root_dir}/zot.log"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": ["https://localhost:${zot_minimal_port}"],
                    "onDemand": true,
                    "stream": true,
                    "maxConcurrentStreams": ${zot_stream_max_concurrent_streams},
                    "certDir": "${zot_stream_capped_cert_dir}",
                    "content": [{"prefix": "**"}]
                }
            ]
        }
    }
}
EOF

    zot_serve ${ZOT_MINIMAL_PATH} ${zot_minimal_config_file}
    wait_zot_reachable ${zot_minimal_port} https

    # Seed the upstream with both images. This is setup, not the path under test, so
    # --dest-tls-verify=false is fine.
    skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_minimal_port}/golang:1.20
    skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/busybox:1.36 \
        docker://127.0.0.1:${zot_minimal_port}/busybox:1.36

    seed_multiarch_index ${zot_minimal_port}

    zot_serve ${ZOT_PATH} ${zot_stream_config_file}
    wait_zot_reachable ${zot_stream_port}

    zot_serve ${ZOT_PATH} ${zot_stream_capped_config_file}
    wait_zot_reachable ${zot_stream_capped_port}
}

function teardown_file() {
    zot_stop_all
}

# Seeds multiarch:latest on the upstream: an OCI index whose two platform children are the
# golang:1.20 (linux/amd64) and busybox:1.36 (linux/arm64) fixtures, so no extra image is fetched.
# The children are pushed by tag only so the index can reference them; the platforms are labels,
# zot doesn't check them against the configs. Child digests are saved for the tests.
function seed_multiarch_index() {
    local port=$1
    local upstream="https://127.0.0.1:${port}/v2/multiarch"
    local accept="Accept: application/vnd.oci.image.manifest.v1+json"

    skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 docker://127.0.0.1:${port}/multiarch:amd64
    skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/busybox:1.36 docker://127.0.0.1:${port}/multiarch:arm64

    local amd64_digest amd64_size arm64_digest arm64_size
    amd64_digest=$(manifest_digest "${upstream}/manifests/amd64")
    amd64_size=$(curl -s -k -H "${accept}" "${upstream}/manifests/amd64" | wc -c)
    arm64_digest=$(manifest_digest "${upstream}/manifests/arm64")
    arm64_size=$(curl -s -k -H "${accept}" "${upstream}/manifests/arm64" | wc -c)

    echo "${amd64_digest}" > ${BATS_FILE_TMPDIR}/multiarch_amd64.digest
    echo "${arm64_digest}" > ${BATS_FILE_TMPDIR}/multiarch_arm64.digest

    jq -n -c \
        --arg amd64_digest "${amd64_digest}" --argjson amd64_size "${amd64_size}" \
        --arg arm64_digest "${arm64_digest}" --argjson arm64_size "${arm64_size}" \
        '{
            schemaVersion: 2,
            mediaType: "application/vnd.oci.image.index.v1+json",
            manifests: [
                {mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $amd64_digest,
                 size: $amd64_size, platform: {os: "linux", architecture: "amd64"}},
                {mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $arm64_digest,
                 size: $arm64_size, platform: {os: "linux", architecture: "arm64"}}
            ]
        }' > ${BATS_FILE_TMPDIR}/multiarch_index.json

    curl -s -k --fail -X PUT -H "Content-Type: application/vnd.oci.image.index.v1+json" \
        --data-binary @${BATS_FILE_TMPDIR}/multiarch_index.json \
        "${upstream}/manifests/latest"
}

function teardown() {
    echo "zot minimal (upstream) logs"
    cat ${BATS_FILE_TMPDIR}/zot-minimal/zot.log
    echo "zot stream (downstream) logs"
    cat ${BATS_FILE_TMPDIR}/zot-stream/zot.log
    echo "zot stream capped (downstream) logs"
    cat ${BATS_FILE_TMPDIR}/zot-stream-capped/zot.log
}

# True once the registry's catalog holds at least $2 repos. Polled because the image that wins the
# cap takes the slower streaming path.
function catalog_has_at_least() {
    local port=$1
    local want=$2
    local count
    count=$(curl -s "http://127.0.0.1:${port}/v2/_catalog" | jq '.repositories | length')
    [ "${count}" -ge "${want}" ]
}

# Prints the manifest digest a registry serves for repo:reference (-k for the self-signed
# upstream).
function manifest_digest() {
    local url=$1
    curl -s -k -D - -o /dev/null \
        -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
        "${url}" | grep -i "docker-content-digest" | tr -d '\r' | awk '{print $2}'
}

@test "sync streaming: concurrent pulls of the same not-yet-synced tag all succeed with matching content" {
    zot_minimal_port=$(cat ${BATS_FILE_TMPDIR}/zot_min.port)
    zot_stream_port=$(cat ${BATS_FILE_TMPDIR}/zot_stream.port)

    local upstream_url="https://127.0.0.1:${zot_minimal_port}/v2/golang/manifests/1.20"
    local downstream_url="http://127.0.0.1:${zot_stream_port}/v2/golang/manifests/1.20"

    local upstream_digest
    upstream_digest=$(manifest_digest "${upstream_url}")
    [ -n "${upstream_digest}" ]

    local num_concurrent=10
    local results_dir="${BATS_TEST_TMPDIR}/results"
    mkdir -p "${results_dir}"

    local pids=()
    for i in $(seq 1 ${num_concurrent}); do
        (
            code=$(curl -s -o /dev/null -w "%{http_code}" \
                -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
                "${downstream_url}")
            echo "${code}" > "${results_dir}/manifest_${i}.code"
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "${pid}"
    done

    for i in $(seq 1 ${num_concurrent}); do
        run cat "${results_dir}/manifest_${i}.code"
        [ "$output" = "200" ]
    done

    # Pull every blob from several clients while the background sync is still running; this is what
    # exercises the blob streaming path. Checking digests proves chunked delivery didn't corrupt or
    # truncate anything.
    local manifest_json
    manifest_json=$(curl -s \
        -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
        "${downstream_url}")

    local blob_digests
    blob_digests=$(echo "${manifest_json}" | jq -r '[.config.digest] + [.layers[].digest] | .[]')
    [ -n "${blob_digests}" ]

    local blob_results_dir="${BATS_TEST_TMPDIR}/blob_results"
    mkdir -p "${blob_results_dir}"

    local blob_pids=()
    local blob_idx=0

    for digest in ${blob_digests}; do
        for c in 1 2 3; do
            blob_idx=$((blob_idx+1))
            (
                expected="${digest#sha256:}"
                actual=$(curl -s "http://127.0.0.1:${zot_stream_port}/v2/golang/blobs/${digest}" | sha256sum | awk '{print $1}')
                if [ "${actual}" = "${expected}" ]; then
                    echo "ok" > "${blob_results_dir}/blob_${blob_idx}.result"
                else
                    echo "mismatch: digest ${digest} got sha256:${actual}" > "${blob_results_dir}/blob_${blob_idx}.result"
                fi
            ) &
            blob_pids+=($!)
        done
    done

    for pid in "${blob_pids[@]}"; do
        wait "${pid}"
    done

    for f in "${blob_results_dir}"/blob_*.result; do
        run cat "${f}"
        [ "$output" = "ok" ]
    done

    # Give the background sync time to commit the image.
    run wait_for_string "successfully synced image" "${BATS_FILE_TMPDIR}/zot-stream/zot.log" "2m"
    [ "$status" -eq 0 ]

    local downstream_digest
    downstream_digest=$(manifest_digest "${downstream_url}")
    [ "${downstream_digest}" = "${upstream_digest}" ]

    # The concurrent requests must share roughly one background sync, not N. Counted from the
    # sync's start log (only the request that stages starts one). Not exactly 1: a later request
    # can land just as the first sync unstages and start one more.
    run grep -c "starting on-demand image sync" "${BATS_FILE_TMPDIR}/zot-stream/zot.log"
    [ "${output}" -lt "${num_concurrent}" ]

    # A second pull, now fully local: the tag is still checked upstream, but its digest is
    # unchanged, so nothing is staged and no stream is held.
    local log_file=${BATS_FILE_TMPDIR}/zot-stream/zot.log
    local streams_before
    streams_before=$(count_log_lines "adding blob to active stream" "${log_file}")

    run curl -s -o /dev/null -w "%{http_code}" "${downstream_url}"
    [ "$output" = "200" ]

    run bash -c "grep 'image already synced locally' '${log_file}' | grep -q '\"repo\":\"golang\"'"
    [ "$status" -eq 0 ]

    [ "$(count_log_lines "adding blob to active stream" "${log_file}")" -eq "${streams_before}" ]
}

@test "sync streaming: concurrent pulls of different tags all succeed even when maxConcurrentStreams is exceeded" {
    zot_minimal_port=$(cat ${BATS_FILE_TMPDIR}/zot_min.port)
    zot_stream_capped_port=$(cat ${BATS_FILE_TMPDIR}/zot_stream_capped.port)

    local results_dir="${BATS_TEST_TMPDIR}/results_capped"
    mkdir -p "${results_dir}"

    local tags=("golang:1.20" "busybox:1.36")
    local pids=()
    local idx=0

    # Several clients per tag, all tags at once: the cap (fits one image, not both) guarantees
    # contention.
    for tag in "${tags[@]}"; do
        local repo="${tag%%:*}"
        local ref="${tag##*:}"

        for i in 1 2 3; do
            idx=$((idx+1))
            (
                code=$(curl -s -o /dev/null -w "%{http_code}" \
                    -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
                    "http://127.0.0.1:${zot_stream_capped_port}/v2/${repo}/manifests/${ref}")
                echo "${code}" > "${results_dir}/pull_${idx}.code"
            ) &
            pids+=($!)
        done
    done

    for pid in "${pids[@]}"; do
        wait "${pid}"
    done

    for f in "${results_dir}"/pull_*.code; do
        run cat "${f}"
        [ "$output" = "200" ]
    done

    # Both images must end up committed despite the cap. Poll, since the cap winner takes the
    # slower streaming path.
    run retry_until_success 24 5 catalog_has_at_least "${zot_stream_capped_port}" 2
    [ "$status" -eq 0 ]

    # The cap must really have been exercised: at least one tag fell back and at least one
    # streamed.
    run grep -c "max concurrent streams reached, falling back to non-streaming on-demand sync" \
        "${BATS_FILE_TMPDIR}/zot-stream-capped/zot.log"
    [ "${output}" -ge 1 ]

    run grep -c "syncing image in the background" "${BATS_FILE_TMPDIR}/zot-stream-capped/zot.log"
    [ "${output}" -ge 1 ]
}

@test "sync streaming: referrers lookup racing an in-progress background sync never gets a 500" {
    zot_stream_port=$(cat ${BATS_FILE_TMPDIR}/zot_stream.port)

    # busybox hasn't been touched on zot-stream yet, so this GET really starts streaming and a
    # background sync from scratch.
    local repo="busybox"
    local ref="1.36"
    local downstream_manifest_url="http://127.0.0.1:${zot_stream_port}/v2/${repo}/manifests/${ref}"

    local subject_digest
    subject_digest=$(manifest_digest "${downstream_manifest_url}")
    [ -n "${subject_digest}" ]

    local downstream_referrers_url="http://127.0.0.1:${zot_stream_port}/v2/${repo}/referrers/${subject_digest}"

    # Clients look up referrers right after getting a manifest. While the streamed image is still
    # committing, the repo can exist without index.json; GetReferrers must return an empty 200
    # there (it used to 500). Fire bursts of lookups while the sync runs and record every status.
    local codes_dir="${BATS_TEST_TMPDIR}/referrers_codes"
    mkdir -p "${codes_dir}"
    local n=0

    local deadline=$((SECONDS + 30))
    while [ ${SECONDS} -lt ${deadline} ]; do
        local pids=()
        for i in $(seq 1 10); do
            n=$((n+1))
            (
                code=$(curl -s -o /dev/null -w "%{http_code}" "${downstream_referrers_url}")
                echo "${code}" > "${codes_dir}/${n}.code"
            ) &
            pids+=($!)
        done

        for pid in "${pids[@]}"; do
            wait "${pid}"
        done

        if grep "successfully synced image" "${BATS_FILE_TMPDIR}/zot-stream/zot.log" \
            | grep -q "\"repo\":\"${repo}\""; then
            break
        fi
    done

    run bash -c "grep -h -c '^500$' '${codes_dir}'/*.code | awk '{sum+=\$1} END{print sum+0}'"
    echo "500 responses seen: ${output}"
    [ "${output}" = "0" ]

    run bash -c "grep -h -c '^200$' '${codes_dir}'/*.code | awk '{sum+=\$1} END{print sum+0}'"
    echo "200 responses seen: ${output}"
    [ "${output}" -gt "0" ]
}

# Count of log lines containing $1 (0 when none; grep -c exits 1 on no match).
function count_log_lines() {
    grep -c "$1" "$2" || true
}

# True once zot logged "successfully synced image" for repo $1, reference $2.
function synced_in_log() {
    grep "successfully synced image" "$3" | grep "\"repo\":\"$1\"" | grep -q "\"reference\":\"$2\""
}

# True once no stream temp file is left under the staging root $1.
function no_stream_temp_files() {
    [ -z "$(find "$1/_stream" -type f 2>/dev/null)" ]
}

@test "sync streaming: multi-arch index is synced sparsely and only the requested platform streams" {
    zot_minimal_port=$(cat ${BATS_FILE_TMPDIR}/zot_min.port)
    zot_stream_port=$(cat ${BATS_FILE_TMPDIR}/zot_stream.port)

    local zot_stream_root_dir=${BATS_FILE_TMPDIR}/zot-stream
    local log_file=${zot_stream_root_dir}/zot.log
    local amd64_digest arm64_digest
    amd64_digest=$(cat ${BATS_FILE_TMPDIR}/multiarch_amd64.digest)
    arm64_digest=$(cat ${BATS_FILE_TMPDIR}/multiarch_arm64.digest)

    local index_accept="Accept: application/vnd.oci.image.index.v1+json"
    local downstream="http://127.0.0.1:${zot_stream_port}/v2/multiarch"

    local upstream_index_digest
    upstream_index_digest=$(curl -s -k -D - -o /dev/null -H "${index_accept}" \
        "https://127.0.0.1:${zot_minimal_port}/v2/multiarch/manifests/latest" |
        grep -i "docker-content-digest" | tr -d '\r' | awk '{print $2}')
    [ -n "${upstream_index_digest}" ]

    # The index GET must stage nothing: no stream is reserved for any platform's blobs.
    local streams_before
    streams_before=$(count_log_lines "adding blob to active stream" "${log_file}")

    run curl -s -D ${BATS_TEST_TMPDIR}/index.headers -o ${BATS_TEST_TMPDIR}/index.json \
        -w "%{http_code}" -H "${index_accept}" "${downstream}/manifests/latest"
    [ "$output" = "200" ]

    run bash -c "grep -i docker-content-digest ${BATS_TEST_TMPDIR}/index.headers | tr -d '\r' | awk '{print \$2}'"
    [ "$output" = "${upstream_index_digest}" ]

    run jq -r '.manifests | length' ${BATS_TEST_TMPDIR}/index.json
    [ "$output" = "2" ]

    run bash -c "grep 'image index is not streamed' '${log_file}' | grep -q '\"repo\":\"multiarch\"'"
    [ "$status" -eq 0 ]

    [ "$(count_log_lines "adding blob to active stream" "${log_file}")" -eq "${streams_before}" ]

    # Sparse, as on the plain on-demand path: neither platform manifest was copied with the index.
    [ ! -f "${zot_stream_root_dir}/multiarch/blobs/sha256/${amd64_digest#sha256:}" ]
    [ ! -f "${zot_stream_root_dir}/multiarch/blobs/sha256/${arm64_digest#sha256:}" ]

    # The client's platform manifest GET (by digest) is what stages and streams that platform.
    run curl -s -o ${BATS_TEST_TMPDIR}/amd64.json -w "%{http_code}" \
        -H "Accept: application/vnd.oci.image.manifest.v1+json" "${downstream}/manifests/${amd64_digest}"
    [ "$output" = "200" ]

    run bash -c "sha256sum ${BATS_TEST_TMPDIR}/amd64.json | awk '{print \"sha256:\" \$1}'"
    [ "$output" = "${amd64_digest}" ]

    run bash -c "grep 'syncing image in the background' '${log_file}' | grep '\"repo\":\"multiarch\"' | grep -q '\"reference\":\"${amd64_digest}\"'"
    [ "$status" -eq 0 ]

    [ "$(count_log_lines "adding blob to active stream" "${log_file}")" -gt "${streams_before}" ]

    # Pull that platform's blobs while its background sync runs, checking content.
    local blob_digests
    blob_digests=$(jq -r '[.config.digest] + [.layers[].digest] | .[]' ${BATS_TEST_TMPDIR}/amd64.json)
    [ -n "${blob_digests}" ]

    local blob_results_dir="${BATS_TEST_TMPDIR}/multiarch_blob_results"
    mkdir -p "${blob_results_dir}"

    local blob_pids=()
    local blob_idx=0

    for digest in ${blob_digests}; do
        blob_idx=$((blob_idx+1))
        (
            expected="${digest#sha256:}"
            actual=$(curl -s "${downstream}/blobs/${digest}" | sha256sum | awk '{print $1}')
            if [ "${actual}" = "${expected}" ]; then
                echo "ok" > "${blob_results_dir}/blob_${blob_idx}.result"
            else
                echo "mismatch: digest ${digest} got sha256:${actual}" > "${blob_results_dir}/blob_${blob_idx}.result"
            fi
        ) &
        blob_pids+=($!)
    done

    for pid in "${blob_pids[@]}"; do
        wait "${pid}"
    done

    for f in "${blob_results_dir}"/blob_*.result; do
        run cat "${f}"
        [ "$output" = "ok" ]
    done

    retry_until_success 24 5 synced_in_log multiarch "${amd64_digest}" "${log_file}"

    # Committed under its digest; the other platform was never requested, so it is still absent.
    [ -f "${zot_stream_root_dir}/multiarch/blobs/sha256/${amd64_digest#sha256:}" ]
    [ ! -f "${zot_stream_root_dir}/multiarch/blobs/sha256/${arm64_digest#sha256:}" ]

    # The stream temp files are deleted once the sync ends and its clients have drained.
    retry_until_success 12 5 no_stream_temp_files "${zot_stream_root_dir}"
}
