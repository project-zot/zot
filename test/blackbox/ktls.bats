# Note: Intended to be run as "make run-blackbox-ktls" (see .github/workflows/tls.yaml)
#       or as part of "make run-blackbox-ci".
#
# Kernel TLS offload ("http.tls.offload": true). The same file covers both kernels:
#   ZOT_KTLS_EXPECT=offload   the tls module is loaded: HTTP/1.1 TLS 1.3 blob GETs
#                             must go through kTLS (zot log + /proc/net/tls_stat)
#   ZOT_KTLS_EXPECT=fallback  the tls module is unavailable: zot must say so and
#                             every connection must still work in userspace TLS
#   unset / auto              pick from /proc/net/tls_stat (local runs)
# In every mode the bytes on the wire must match what was pushed.

load helpers_zot
load ../port_helper

function verify_prerequisites {
    for tool in curl jq openssl skopeo sha256sum; do
        if ! command -v ${tool} >/dev/null 2>&1; then
            echo "you need to install ${tool} as a prerequisite to running the tests" >&3
            return 1
        fi
    done

    return 0
}

function ktls_tx_sw() {
    # Cumulative software kTLS TX sessions; 0 when the tls module is not loaded.
    awk '$1 == "TlsTxSw" { print $2; found=1 } END { if (!found) print 0 }' /proc/net/tls_stat 2>/dev/null || echo 0
}

function setup_file() {
    if ! verify_prerequisites; then
        exit 1
    fi

    local expect=${ZOT_KTLS_EXPECT:-auto}
    if [[ "${expect}" == "auto" ]]; then
        expect=fallback
        [[ -r /proc/net/tls_stat ]] && expect=offload
    fi
    echo "${expect}" > ${BATS_FILE_TMPDIR}/ktls.expect
    echo "kTLS expectation: ${expect}" >&3

    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local cert=${BATS_FILE_TMPDIR}/server.cert
    local key=${BATS_FILE_TMPDIR}/server.key
    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    mkdir -p ${zot_root_dir}

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
        -keyout "${key}" -out "${cert}" -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1"

    cat > ${zot_config_file}<<EOF
{
  "distSpecVersion":"1.1.1",
  "storage":{
    "rootDirectory": "${zot_root_dir}"
  },
  "http": {
    "address": "127.0.0.1",
    "port": "${zot_port}",
    "tls": {
      "cert": "${cert}",
      "key": "${key}",
      "offload": true
    }
  },
  "log":{
    "level":"debug",
    "output": "${BATS_FILE_TMPDIR}/zot.log"
  }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port} https

    # A 32 MiB random blob: big enough for many sendfile calls and TLS records.
    local blob=${BATS_FILE_TMPDIR}/blob
    head -c $((32 << 20)) /dev/urandom > ${blob}
    local digest="sha256:$(sha256sum ${blob} | cut -d' ' -f1)"
    echo ${digest} > ${BATS_FILE_TMPDIR}/blob.digest

    local location
    location=$(curl -sk -D - -o /dev/null -X POST "https://127.0.0.1:${zot_port}/v2/ktls/blobs/uploads/" \
        | awk 'tolower($1) == "location:" { print $2 }' | tr -d '\r')
    [[ "${location}" == http* ]] || location="https://127.0.0.1:${zot_port}${location}"
    local sep='?'
    [[ "${location}" == *'?'* ]] && sep='&'
    curl -skf -X PUT -H "Content-Type: application/octet-stream" --data-binary @${blob} \
        "${location}${sep}digest=${digest}"

    ktls_tx_sw > ${BATS_FILE_TMPDIR}/tls_tx_sw.before
}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from teardown_file
    grep -i "kernel TLS" ${BATS_FILE_TMPDIR}/zot.log 2>/dev/null | tail -20 || true
}

function teardown_file() {
    zot_stop_all
}

function blob_url() {
    echo "https://127.0.0.1:$(cat ${BATS_FILE_TMPDIR}/zot.port)/v2/ktls/blobs/$(cat ${BATS_FILE_TMPDIR}/blob.digest)"
}

function assert_blob_body() {
    local got=${1}
    [ "sha256:$(sha256sum ${got} | cut -d' ' -f1)" == "$(cat ${BATS_FILE_TMPDIR}/blob.digest)" ]
}

@test "HTTP/1.1 TLS 1.3 whole blob GET returns the pushed bytes" {
    local out=${BATS_FILE_TMPDIR}/get-whole
    run curl -skf --http1.1 --tlsv1.3 -o ${out} -w '%{http_version}' $(blob_url)
    [ "$status" -eq 0 ]
    [ "$output" == "1.1" ]
    assert_blob_body ${out}
}

@test "HTTP/1.1 TLS 1.3 range GET returns the requested bytes" {
    local out=${BATS_FILE_TMPDIR}/get-range
    local from=$(( (3 << 20) + 17 )) to=$(( (20 << 20) + 5 ))
    run curl -skf --http1.1 --tlsv1.3 -o ${out} -w '%{http_code}' -H "Range: bytes=${from}-${to}" $(blob_url)
    [ "$status" -eq 0 ]
    [ "$output" == "206" ]
    cmp ${out} <(tail -c +$((from + 1)) ${BATS_FILE_TMPDIR}/blob | head -c $((to - from + 1)))
}

@test "every TLS 1.3 cipher suite returns the pushed bytes" {
    local suites=(TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256)
    for suite in "${suites[@]}"; do
        local out=${BATS_FILE_TMPDIR}/get-${suite}
        run curl -skf --http1.1 --tlsv1.3 --tls13-ciphers ${suite} -o ${out} $(blob_url)
        [ "$status" -eq 0 ]
        assert_blob_body ${out}
    done
}

@test "TLS 1.2 (never offloaded) returns the pushed bytes" {
    local out=${BATS_FILE_TMPDIR}/get-tls12
    run curl -skf --http1.1 --tlsv1.2 --tls-max 1.2 -o ${out} $(blob_url)
    [ "$status" -eq 0 ]
    assert_blob_body ${out}
}

@test "HTTP/2 is still negotiated and returns the pushed bytes" {
    local out=${BATS_FILE_TMPDIR}/get-h2
    run curl -skf --http2 -o ${out} -w '%{http_version}' $(blob_url)
    [ "$status" -eq 0 ]
    [ "$output" == "2" ]
    assert_blob_body ${out}
}

@test "plain HTTP to the HTTPS port still gets 400" {
    run curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$(cat ${BATS_FILE_TMPDIR}/zot.port)/v2/"
    [ "$output" == "400" ]
}

@test "skopeo (Go client, no TLS session cache) pushes and pulls an image" {
    local zot_port=$(cat ${BATS_FILE_TMPDIR}/zot.port)
    local src=${BATS_FILE_TMPDIR}/src-oci dst=${BATS_FILE_TMPDIR}/dst-oci

    # Public image: --src-no-creds keeps stale local ghcr credentials from turning
    # this into a 403.
    skopeo --insecure-policy copy --format=oci --src-no-creds \
        docker://ghcr.io/project-zot/test-images/busybox:1.36 oci:${src}:1.36
    run skopeo --insecure-policy copy --dest-tls-verify=false oci:${src}:1.36 \
        docker://127.0.0.1:${zot_port}/busybox:1.36
    [ "$status" -eq 0 ]
    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:${zot_port}/busybox:1.36 oci:${dst}:1.36
    [ "$status" -eq 0 ]
    diff <(cd ${src}/blobs && find . -type f | sort | xargs sha256sum) \
         <(cd ${dst}/blobs && find . -type f | sort | xargs sha256sum)
}

@test "offload outcome matches the kernel" {
    local log=${BATS_FILE_TMPDIR}/zot.log
    local before=$(cat ${BATS_FILE_TMPDIR}/tls_tx_sw.before) after=$(ktls_tx_sw)
    echo "TlsTxSw before=${before} after=${after}" >&3

    # TLS 1.2 and h2 connections must never be offloaded, whatever the kernel.
    grep -q '"reason":"tls-version"' ${log}
    grep -q '"reason":"alpn"' ${log}

    case "$(cat ${BATS_FILE_TMPDIR}/ktls.expect)" in
    offload)
        grep -q "kernel TLS offload enabled" ${log}
        grep -q "kernel TLS offload active" ${log}
        # run + status: bash exempts "! cmd" from errexit, so a bare
        # negated grep would not fail the test on a match.
        run grep -q "kernel TLS offload failed" ${log}
        [ "$status" -eq 1 ]
        # whole, range, 3 suites and the skopeo connections at least
        [ $((after - before)) -ge 5 ]
        ;;
    fallback)
        grep -q "kernel TLS offload requested but unavailable" ${log}
        # run + status: bash exempts "! cmd" from errexit, so a bare
        # negated grep would not fail the test on a match.
        run grep -q "kernel TLS offload active" ${log}
        [ "$status" -eq 1 ]
        grep -q '"reason":"kernel"' ${log}
        [ "${after}" -eq "${before}" ]
        ;;
    *)
        echo "unknown ZOT_KTLS_EXPECT" >&3
        return 1
        ;;
    esac
}
