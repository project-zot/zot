# Note: Intended to be run as "make run-blackbox-sync-streaming-stress"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()
#
# Large-file, many-clients stress coverage for streaming on-demand sync
# (extensions.sync.registries[].stream): a single very large (default 20GiB) layer, requested by
# many concurrent clients before it is staged locally, must stream correctly to every client
# (matching content, no corruption/truncation from chunked delivery) while the background sync
# commits the full layer to local storage - all within a bounded time budget.
#
# This is deliberately separate from sync_streaming.bats (small fixture images, run on every PR):
# a 20GiB layer needs real disk and time budget on the order of minutes, so it belongs in the
# nightly stress lane, not the per-PR gate.

load helpers_zot
load helpers_wait
load ../port_helper

# Tunables, overridable via env for local runs without editing this file.
stress_layer_size_mb=${SYNC_STREAMING_STRESS_LAYER_SIZE_MB:-20480} # 20GiB default
stress_num_clients=${SYNC_STREAMING_STRESS_CLIENTS:-8}

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

    if ! command -v oras >/dev/null 2>&1; then
        echo "you need to install oras as a prerequisite to running the tests" >&3
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

    local zot_minimal_root_dir=${BATS_FILE_TMPDIR}/zot-minimal
    local zot_minimal_config_file=${BATS_FILE_TMPDIR}/zot_minimal_config.json
    local zot_minimal_cert_file=${BATS_FILE_TMPDIR}/zot_minimal_server.cert
    local zot_minimal_key_file=${BATS_FILE_TMPDIR}/zot_minimal_server.key

    local zot_stream_root_dir=${BATS_FILE_TMPDIR}/zot-stream
    local zot_stream_config_file=${BATS_FILE_TMPDIR}/zot_stream_config.json
    local zot_stream_cert_dir=${BATS_FILE_TMPDIR}/zot-stream-certs

    mkdir -p ${zot_minimal_root_dir}
    mkdir -p ${zot_stream_root_dir}
    mkdir -p ${zot_stream_cert_dir}

    # Streaming requires a TLS-verified upstream (see validateRegistryStreamingSyncConfig) - a
    # self-signed cert for the upstream zot_minimal, trusted by the downstream via its sync
    # registry's certDir, so the sync client performs real certificate/hostname verification
    # rather than turning it off.
    generate_self_signed_cert "${zot_minimal_cert_file}" "${zot_minimal_key_file}" "localhost"
    cp "${zot_minimal_cert_file}" "${zot_stream_cert_dir}/ca.crt"

    zot_minimal_port=$(get_free_port_for_service "zot_min")
    echo ${zot_minimal_port} > ${BATS_FILE_TMPDIR}/zot_min.port

    zot_stream_port=$(get_free_port_for_service "zot_stream")
    echo ${zot_stream_port} > ${BATS_FILE_TMPDIR}/zot_stream.port

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

    # maxConcurrentStreams is sized to the client count (plus headroom) so this run exercises
    # many clients sharing one real stream, not the cap-fallback path - that contention scenario
    # is already covered, at small scale, by sync_streaming.bats.
    local zot_stream_max_concurrent_streams=$((stress_num_clients + 4))

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
                    "maxConcurrentStreams": ${zot_stream_max_concurrent_streams},
                    "certDir": "${zot_stream_cert_dir}",
                    "content": [{"prefix": "**"}]
                }
            ]
        }
    }
}
EOF

    zot_serve ${ZOT_MINIMAL_PATH} ${zot_minimal_config_file}
    wait_zot_reachable ${zot_minimal_port} https

    # Build one large layer locally, then push it to the upstream as a single-layer OCI image.
    # /dev/zero keeps generation fast (no entropy cost) - the point of this test is exercising the
    # streaming/chunked-delivery mechanism at scale, not layer compressibility or content entropy,
    # and every byte is still actually read (hashed on push, streamed on pull) either way.
    local big_layer_file=${BATS_FILE_TMPDIR}/big-layer.bin
    dd if=/dev/zero of="${big_layer_file}" bs=1M count=${stress_layer_size_mb} status=progress

    # Pushing here is just test-data setup (not the streaming sync path under test), so
    # --insecure (skip TLS verify of zot_minimal's self-signed cert) is fine.
    run oras push --insecure "127.0.0.1:${zot_minimal_port}/bigimage:v1" \
        "${big_layer_file}:application/octet-stream"
    [ "${status}" -eq 0 ]

    zot_serve ${ZOT_PATH} ${zot_stream_config_file}
    wait_zot_reachable ${zot_stream_port}
}

function teardown_file() {
    zot_stop_all
}

function teardown() {
    echo "zot minimal (upstream) log tail"
    tail -n 200 ${BATS_FILE_TMPDIR}/zot-minimal/zot.log
    echo "zot stream (downstream) log tail"
    tail -n 200 ${BATS_FILE_TMPDIR}/zot-stream/zot.log
}

# returns the manifest digest a registry serves for repo:reference on stdout. -k lets this also
# hit the TLS upstream (self-signed).
function manifest_digest() {
    local url=$1
    curl -s -k -D - -o /dev/null \
        -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
        "${url}" | grep -i "docker-content-digest" | tr -d '\r' | awk '{print $2}'
}

@test "sync streaming: many concurrent clients pull a large not-yet-synced layer with matching content" {
    zot_minimal_port=$(cat ${BATS_FILE_TMPDIR}/zot_min.port)
    zot_stream_port=$(cat ${BATS_FILE_TMPDIR}/zot_stream.port)

    local upstream_url="https://127.0.0.1:${zot_minimal_port}/v2/bigimage/manifests/v1"
    local downstream_url="http://127.0.0.1:${zot_stream_port}/v2/bigimage/manifests/v1"

    local upstream_digest
    upstream_digest=$(manifest_digest "${upstream_url}")
    [ -n "${upstream_digest}" ]

    # Fire every client's manifest GET at once, before anything is staged locally: this is what
    # actually races FetchManifestForStream's staging/singleflight paths under real concurrency,
    # not just the later blob pulls below.
    local results_dir="${BATS_TEST_TMPDIR}/results"
    mkdir -p "${results_dir}"

    local pids=()
    for i in $(seq 1 ${stress_num_clients}); do
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

    for i in $(seq 1 ${stress_num_clients}); do
        run cat "${results_dir}/manifest_${i}.code"
        [ "$output" = "200" ]
    done

    local manifest_json
    manifest_json=$(curl -s \
        -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
        "${downstream_url}")

    local layer_digest
    layer_digest=$(echo "${manifest_json}" | jq -r '.layers[0].digest')
    [ -n "${layer_digest}" ]
    [ "${layer_digest}" != "null" ]

    # Many concurrent clients pull the large layer at once, each piped straight into sha256sum
    # rather than materialized on disk (stress_num_clients full local copies of a 20GiB layer
    # would need far more disk than this is worth) - this is the actual point of the test: every
    # client must get complete, uncorrupted content while the chunked delivery is still arriving
    # from upstream and the background sync is committing it locally at the same time.
    local blob_results_dir="${BATS_TEST_TMPDIR}/blob_results"
    mkdir -p "${blob_results_dir}"

    local expected="${layer_digest#sha256:}"
    local blob_pids=()

    for i in $(seq 1 ${stress_num_clients}); do
        (
            actual=$(curl -s "http://127.0.0.1:${zot_stream_port}/v2/bigimage/blobs/${layer_digest}" |
                sha256sum | awk '{print $1}')
            if [ "${actual}" = "${expected}" ]; then
                echo "ok" > "${blob_results_dir}/blob_${i}.result"
            else
                echo "mismatch: expected sha256:${expected} got sha256:${actual}" > "${blob_results_dir}/blob_${i}.result"
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

    # The background sync needs a much larger time budget than the small-fixture test: committing
    # a full ~20GiB layer to local storage takes real minutes, not seconds, even over loopback.
    run wait_for_string "successfully synced image" "${BATS_FILE_TMPDIR}/zot-stream/zot.log" "30m"
    [ "$status" -eq 0 ]

    local downstream_digest
    downstream_digest=$(manifest_digest "${downstream_url}")
    [ "${downstream_digest}" = "${upstream_digest}" ]

    # a second pull, now fully local, must not touch the stream cache/upstream at all
    run curl -s -o /dev/null -w "%{http_code}" "${downstream_url}"
    [ "$output" = "200" ]
}
