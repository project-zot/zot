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

    # maxConcurrentStreams deliberately set to 1: concurrent pulls of DIFFERENT tags below will
    # exceed it, so this proves the graceful-fallback path (once the cap is hit, on-demand serves
    # via the ordinary non-streaming sync instead of failing the request).
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
                    "maxConcurrentStreams": 1,
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

    # the background sync started by streaming needs a moment to finish committing the full
    # image (config + every layer) to local storage
    run wait_for_string "successfully synced image" "${BATS_FILE_TMPDIR}/zot-stream/zot.log" "2m"
    [ "$status" -eq 0 ]

    local downstream_digest
    downstream_digest=$(manifest_digest "${downstream_url}")
    [ "${downstream_digest}" = "${upstream_digest}" ]

    # concurrent requests for the same image must have collapsed onto a single background sync,
    # not raced upstream N times independently
    run grep -c "already demanded" "${BATS_FILE_TMPDIR}/zot-stream/zot.log"
    [ "${output}" -ge "1" ]

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

    # each tag pulled by several concurrent clients at once, all tags started together: with
    # maxConcurrentStreams=1, this guarantees more than one tag's blobs are contending for the
    # single streaming slot at some point during the run.
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

    run curl -s http://127.0.0.1:${zot_stream_capped_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories | length') -ge 2 ]
}
