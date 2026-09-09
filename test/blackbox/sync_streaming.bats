# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()
#
# Contention/load coverage for streaming on-demand sync (extensions.sync.registries[].stream):
# many concurrent clients pulling the same not-yet-synced tag must all get a complete, correct
# response while the image streams in from upstream, concurrent pulls of DIFFERENT tags must not
# fail even when they exceed maxConcurrentStreams (on-demand falls back to the ordinary
# non-streaming path once the cap is hit rather than erroring), and the background sync must
# still fully commit the image to local storage once every client has been served.

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

# Generate a self-signed certificate with the given CN/SAN. Go's TLS client (used by zot's sync
# client for real, non-insecure hostname verification below) requires a SAN entry - a CN alone is
# not enough since Go 1.15.
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

    # Derive maxConcurrentStreams from the fixtures themselves rather than hardcoding it: it must
    # be big enough to fully stage ONE of these images (manifest + config + every layer, all
    # staged as distinct blobs by StoreImageForStreaming) but too small for both at once, so the
    # "different tags" test below actually forces one tag to win the cap while the other falls
    # back - a cap of 1 would make every single request (even non-concurrent) exceed the cap on
    # its own second blob, never exercising real cross-tag contention.
    # Query via skopeo (same "oci:<dir>:<tag>" ref used everywhere else in this file) rather than
    # hand-parsing the OCI layout on disk: skopeo's oci: destination strips the trailing ":<tag>"
    # into the image ref, so the layout actually lands at "${TEST_DATA_DIR}/golang" (no colon),
    # not a directory literally named "golang:1.20" - inspect avoids depending on that layout
    # detail at all.
    local golang_blob_count busybox_blob_count
    golang_blob_count=$(skopeo inspect --raw "oci:${TEST_DATA_DIR}/golang:1.20" |
        jq '([.config.digest] + [.layers[].digest]) | unique | length')
    busybox_blob_count=$(skopeo inspect --raw "oci:${TEST_DATA_DIR}/busybox:1.36" |
        jq '([.config.digest] + [.layers[].digest]) | unique | length')

    # +1 for each manifest itself, which is staged as a blob in its own right too.
    local zot_stream_max_concurrent_streams
    zot_stream_max_concurrent_streams=$(( (golang_blob_count > busybox_blob_count ? golang_blob_count : busybox_blob_count) + 1 ))

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

    # Streaming requires a TLS-verified upstream (see validateRegistryStreamingSyncConfig) - a
    # self-signed cert for the upstream zot_minimal, trusted by each downstream via its sync
    # registry's certDir, so the sync client performs real certificate/hostname verification
    # rather than turning it off.
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

    # A single upstream tag, pulled by many concurrent clients at once: exercises the shared
    # in-flight stream (activeStreams keyed by digest) and the singleflight-deduped background
    # sync, both under real HTTP concurrency rather than in-process goroutines.
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
                    "preserveDigest": true,
                    "stream": true,
                    "certDir": "${zot_stream_cert_dir}",
                    "content": [{"prefix": "**"}]
                }
            ]
        }
    }
}
EOF

    # Sized to stage one of golang:1.20/busybox:1.36 in full but not both together (see
    # zot_stream_max_concurrent_streams above): concurrent pulls of DIFFERENT tags below then
    # genuinely contend for the cap, so this proves the graceful-fallback path (once the cap is
    # hit, on-demand serves via the ordinary non-streaming sync instead of failing the request).
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
                    "preserveDigest": true,
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

    # seed the upstream with both images before any downstream sync starts. Pushing here is just
    # test-data setup (not the streaming sync path under test), so --dest-tls-verify=false is fine.
    skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_minimal_port}/golang:1.20
    skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/busybox:1.36 \
        docker://127.0.0.1:${zot_minimal_port}/busybox:1.36

    zot_serve ${ZOT_PATH} ${zot_stream_config_file}
    wait_zot_reachable ${zot_stream_port}

    zot_serve ${ZOT_PATH} ${zot_stream_capped_config_file}
    wait_zot_reachable ${zot_stream_capped_port}
}

function teardown_file() {
    zot_stop_all
}

function teardown() {
    echo "zot minimal (upstream) logs"
    cat ${BATS_FILE_TMPDIR}/zot-minimal/zot.log
    echo "zot stream (downstream) logs"
    cat ${BATS_FILE_TMPDIR}/zot-stream/zot.log
    echo "zot stream capped (downstream) logs"
    cat ${BATS_FILE_TMPDIR}/zot-stream-capped/zot.log
}

# returns the manifest digest a registry serves for repo:reference on stdout. -k is a no-op
# against the plain-http downstream URLs and lets this also hit the TLS upstream (self-signed).
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

    # Pull every blob (config + each layer) the manifest above references, from several
    # concurrent clients each, while the background sync from the manifest pulls above is still
    # in flight - this is what actually exercises streamBlobToClient/ConnectClient (the manifest
    # GETs alone never touch /blobs/<digest>). Digest-checking the downloaded bytes verifies
    # chunked delivery didn't corrupt or truncate content while it was still arriving upstream.
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

    # the background sync started by streaming needs a moment to finish committing the full
    # image (config + every layer) to local storage
    run wait_for_string "successfully synced image" "${BATS_FILE_TMPDIR}/zot-stream/zot.log" "2m"
    [ "$status" -eq 0 ]

    local downstream_digest
    downstream_digest=$(manifest_digest "${downstream_url}")
    [ "${downstream_digest}" = "${upstream_digest}" ]

    # The num_concurrent manifest requests above must have collapsed onto (approximately) one
    # background sync, not raced upstream N times independently. Checked via the real sync's own
    # start log, not singleflight's "already demanded" dedup-hit log: StoreImageForStreaming's own
    # race handling (only the caller that wins staging launches a background sync at all - see
    # on_demand.go) means singleflight now typically has nothing left to dedupe, since redundant
    # callers never reach it in the first place. Not pinned to exactly 1: the manifest_json fetch
    # below is a genuinely separate, later request, and on rare timing can land just as the first
    # sync's own completion is purging the stream cache (RemoveStreamingImage), triggering one
    # more legitimate resync - still nowhere near num_concurrent independent syncs.
    run grep -c "starting on-demand image sync" "${BATS_FILE_TMPDIR}/zot-stream/zot.log"
    [ "${output}" -lt "${num_concurrent}" ]

    # a second pull, now fully local, must not touch the stream cache/upstream at all
    run curl -s -o /dev/null -w "%{http_code}" "${downstream_url}"
    [ "$output" = "200" ]
}

@test "sync streaming: concurrent pulls of different tags all succeed even when maxConcurrentStreams is exceeded" {
    zot_minimal_port=$(cat ${BATS_FILE_TMPDIR}/zot_min.port)
    zot_stream_capped_port=$(cat ${BATS_FILE_TMPDIR}/zot_stream_capped.port)

    local results_dir="${BATS_TEST_TMPDIR}/results_capped"
    mkdir -p "${results_dir}"

    local tags=("golang:1.20" "busybox:1.36")
    local pids=()
    local idx=0

    # each tag pulled by several concurrent clients at once, all tags started together: the cap
    # (sized in setup_file to fit one of these images but not both) guarantees the two tags'
    # blobs contend for the shared streaming slots at some point during the run.
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

    # both images must eventually be fully committed locally, regardless of the low cap
    run wait_for_string "successfully synced image" "${BATS_FILE_TMPDIR}/zot-stream-capped/zot.log" "2m"
    [ "$status" -eq 0 ]

    # confirm the cap was actually exercised: at least one tag must have hit it and fallen back
    # to a non-streaming sync (the whole point of this test), while at least one other must have
    # gone through the normal streaming path - otherwise the cap sizing above isn't doing its job
    # and this test would degrade back into never really testing contention.
    run grep -c "max concurrent streams reached, falling back to non-streaming on-demand sync" \
        "${BATS_FILE_TMPDIR}/zot-stream-capped/zot.log"
    [ "${output}" -ge 1 ]

    run grep -c "syncing image in the background" "${BATS_FILE_TMPDIR}/zot-stream-capped/zot.log"
    [ "${output}" -ge 1 ]

    run curl -s http://127.0.0.1:${zot_stream_capped_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories | length') -ge 2 ]
}

@test "sync streaming: referrers lookup racing an in-progress background sync never gets a 500" {
    zot_stream_port=$(cat ${BATS_FILE_TMPDIR}/zot_stream.port)

    # "busybox" on zot-stream has not been touched by any earlier test in this file (only
    # "golang" has, in the first test above) - this manifest GET is the very first client
    # request for it, so it really does trigger streaming + a background sync from scratch,
    # rather than being served from an already-committed local copy.
    local repo="busybox"
    local ref="1.36"
    local downstream_manifest_url="http://127.0.0.1:${zot_stream_port}/v2/${repo}/manifests/${ref}"

    local subject_digest
    subject_digest=$(manifest_digest "${downstream_manifest_url}")
    [ -n "${subject_digest}" ]

    local downstream_referrers_url="http://127.0.0.1:${zot_stream_port}/v2/${repo}/referrers/${subject_digest}"

    # Docker/OCI clients issue this referrers lookup automatically right after receiving a
    # manifest. With streaming, the manifest above was served before the background sync
    # finished committing the image locally, so this races that commit: the repo directory may
    # already exist (blobs mid-copy) while index.json does not yet - the exact window
    # pkg/storage/common/common.go's GetReferrers must answer with an empty 200 index for
    # (previously a 500, see the fix). Fire bursts of concurrent lookups for as long as the
    # background sync is still running, recording every status code seen.
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
