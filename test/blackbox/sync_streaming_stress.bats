# Note: Intended to be run as "make run-blackbox-sync-streaming-stress"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()
#
# Stress test for streaming on-demand sync: one very large layer (default 20GiB) requested by many
# clients at once must reach every client intact while the background sync commits it, within a
# time budget.

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

    # Streaming requires a TLS-verified upstream: the downstream trusts this self-signed cert via
    # certDir, so verification stays on.
    generate_self_signed_cert "${zot_minimal_cert_file}" "${zot_minimal_key_file}" "localhost"
    cp "${zot_minimal_cert_file}" "${zot_stream_cert_dir}/ca.crt"

    zot_minimal_port=$(get_free_port_for_service "zot_min")
    echo ${zot_minimal_port} > ${BATS_FILE_TMPDIR}/zot_min.port

    zot_stream_port=$(get_free_port_for_service "zot_stream")
    echo ${zot_stream_port} > ${BATS_FILE_TMPDIR}/zot_stream.port

    # The default 60s read/write timeouts would cut a multi-GiB blob off mid-stream, leaving every
    # client of the shared stream with the same truncated content.
    cat >${zot_minimal_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_minimal_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_minimal_port}",
        "readTimeout": "60m",
        "writeTimeout": "60m",
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

    # Sized above the client count, so this tests many clients sharing one stream, not the cap
    # fallback (sync_streaming.bats covers that).
    local zot_stream_max_concurrent_streams=$((stress_num_clients + 4))

    # Same timeout reasoning as zot_minimal above, for zot_stream's responses to the clients.
    cat >${zot_stream_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_stream_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_stream_port}",
        "compat": ["docker2s2"],
        "readTimeout": "60m",
        "writeTimeout": "60m"
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
                    "maxConcurrentStreams": ${zot_stream_max_concurrent_streams},
                    "certDir": "${zot_stream_cert_dir}",
                    "content": [{"prefix": "**"}]
                }
            ]
        }
    }
}
EOF

    # The upstream runs the full binary: the layer is pushed with oras, which the minimal build
    # doesn't reliably support.
    zot_serve ${ZOT_PATH} ${zot_minimal_config_file}
    wait_zot_reachable ${zot_minimal_port} https

    # Build one large layer and push it as a single-layer image. /dev/zero is fast, and content
    # entropy doesn't matter here: every byte is still hashed and streamed.
    local big_layer_file=${BATS_FILE_TMPDIR}/big-layer.bin
    dd if=/dev/zero of="${big_layer_file}" bs=1M count=${stress_layer_size_mb} status=progress

    # Setup only, so --insecure is fine. big_layer_file is an absolute path, which oras rejects
    # without --disable-path-validation.
    run oras push --insecure --disable-path-validation "127.0.0.1:${zot_minimal_port}/bigimage:v1" \
        "${big_layer_file}:application/octet-stream"
    [ "${status}" -eq 0 ]

    # Delete the source now that the upstream has a copy. Peak disk use is then three copies of the
    # layer, all on this disk, at the downstream's commit: upstream storage, the downstream's
    # staged copy (its stream temp file, hard-linked into its .sync session) and the committed blob.
    rm -f "${big_layer_file}"

    zot_serve ${ZOT_PATH} ${zot_stream_config_file}
    wait_zot_reachable ${zot_stream_port}
}

function teardown_file() {
    zot_stop_all
}

function teardown() {
    echo "zot minimal (upstream) logs"
    cat ${BATS_FILE_TMPDIR}/zot-minimal/zot.log
    echo "zot stream (downstream) logs"
    cat ${BATS_FILE_TMPDIR}/zot-stream/zot.log
}

# Prints the manifest digest a registry serves for repo:reference (-k for the self-signed
# upstream).
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

    # Fire every client's manifest GET at once, before anything is staged, to race
    # FetchManifestForStream's staging under real concurrency.
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

    # Confirm the requests really streamed (its "syncing image in the background" log line) rather
    # than silently taking the plain on-demand path.
    run grep -c "syncing image in the background" "${BATS_FILE_TMPDIR}/zot-stream/zot.log"
    [ "${output}" -ge 1 ]

    local manifest_json
    manifest_json=$(curl -s \
        -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
        "${downstream_url}")

    local layer_digest
    layer_digest=$(echo "${manifest_json}" | jq -r '.layers[0].digest')
    [ -n "${layer_digest}" ]
    [ "${layer_digest}" != "null" ]

    # Many clients pull the layer at once, piped straight into sha256sum (full copies would need
    # too much disk). Every client must get intact content while the layer is still arriving and
    # committing.
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

    # Committing ~20GiB takes minutes, so this needs a much larger budget than the small test.
    run wait_for_string "successfully synced image" "${BATS_FILE_TMPDIR}/zot-stream/zot.log" "60m"
    [ "$status" -eq 0 ]

    local downstream_digest
    downstream_digest=$(manifest_digest "${downstream_url}")
    [ "${downstream_digest}" = "${upstream_digest}" ]

    # A second pull, now fully local, must not touch the stream cache or upstream.
    run curl -s -o /dev/null -w "%{http_code}" "${downstream_url}"
    [ "$output" = "200" ]
}
