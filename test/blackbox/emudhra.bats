# eMudhra CA distrust tests (included in the host-deps CI shard). Run with:
# make run-blackbox-tests BATS_TEST_FILE_PATH=test/blackbox/emudhra.bats

load helpers_zot
load ../port_helper

function verify_prerequisites() {
    local prerequisite
    for prerequisite in curl jq nc mitmdump skopeo; do
        if ! command -v "${prerequisite}" >/dev/null 2>&1; then
            echo "you need to install ${prerequisite} as a prerequisite to running the tests" >&3
            return 1
        fi
    done

    local mitmdump_help
    mitmdump_help=$(mitmdump --help 2>&1)
    if [[ "${mitmdump_help}" != *"--emudhra"* ]]; then
        echo "mitmdump 12.3 or newer with --emudhra support is required" >&3
        return 1
    fi
}

function wait_for_log_entry() {
    local log_file="$1"
    local start_line="$2"
    local expected="$3"
    local deadline=$((SECONDS + 30))

    while [ "${SECONDS}" -lt "${deadline}" ]; do
        if tail -n +"${start_line}" "${log_file}" | grep -Fq "${expected}"; then
            return 0
        fi
        sleep 0.5
    done

    echo "did not find '${expected}' in ${log_file}" >&3
    tail -n 100 "${log_file}" >&3
    return 1
}

function setup_file() {
    if ! verify_prerequisites; then
        exit 1
    fi

    mkdir -p "${TEST_DATA_DIR}"
    skopeo --insecure-policy copy --format=oci \
        docker://ghcr.io/project-zot/golang:1.20 \
        "oci:${TEST_DATA_DIR}/emudhra:latest"

    local mitm_port
    mitm_port=$(get_free_port_for_service "mitm")
    echo "${mitm_port}" > "${BATS_FILE_TMPDIR}/mitm.port"

    mkdir -p "${BATS_FILE_TMPDIR}/mitmproxy-home"
    HOME="${BATS_FILE_TMPDIR}/mitmproxy-home" mitmdump \
        --mode "reverse:http://127.0.0.1:1@${mitm_port}" \
        --listen-host 127.0.0.1 \
        --set connection_strategy=lazy \
        --emudhra \
        > "${BATS_FILE_TMPDIR}/mitmproxy.log" 2>&1 &
    echo "$!" > "${BATS_FILE_TMPDIR}/mitmproxy.pid"

    local deadline=$((SECONDS + 30))
    while ! nc -z 127.0.0.1 "${mitm_port}"; do
        if ! kill -0 "$(cat "${BATS_FILE_TMPDIR}/mitmproxy.pid")" 2>/dev/null; then
            cat "${BATS_FILE_TMPDIR}/mitmproxy.log" >&3
            exit 1
        fi
        if [ "${SECONDS}" -ge "${deadline}" ]; then
            echo "mitmdump did not listen on port ${mitm_port}" >&3
            cat "${BATS_FILE_TMPDIR}/mitmproxy.log" >&3
            exit 1
        fi
        sleep 0.5
    done

    local zot_port
    zot_port=$(get_free_port_for_service "zot")
    echo "${zot_port}" > "${BATS_FILE_TMPDIR}/zot.port"

    local zot_root_dir="${BATS_FILE_TMPDIR}/zot"
    local zot_config_file="${BATS_FILE_TMPDIR}/zot_config.json"
    mkdir -p "${zot_root_dir}"
    cat > "${zot_config_file}" <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "127.0.0.1",
        "port": "${zot_port}"
    },
    "log": {
        "level": "debug",
        "output": "${BATS_FILE_TMPDIR}/zot.log"
    },
    "extensions": {
        "events": {
            "enable": true,
            "sinks": [{
                "type": "http",
                "address": "https://127.0.0.1:${mitm_port}/events",
                "timeout": "10s"
            }]
        },
        "sync": {
            "registries": [{
                "urls": ["https://127.0.0.1:${mitm_port}"],
                "onDemand": true,
                "tlsVerify": true,
                "content": [{
                    "prefix": "**"
                }]
            }]
        }
    }
}
EOF
    zot_serve "${ZOT_PATH}" "${zot_config_file}"
    wait_zot_reachable "${zot_port}"
}

function teardown_file() {
    zot_stop_all

    if [ -f "${BATS_FILE_TMPDIR}/mitmproxy.pid" ]; then
        local mitm_pid
        mitm_pid=$(cat "${BATS_FILE_TMPDIR}/mitmproxy.pid")
        kill "${mitm_pid}" 2>/dev/null || true
        wait "${mitm_pid}" 2>/dev/null || true
    fi
}

@test "event sink rejects a certificate signed by the eMudhra CA" {
    local zot_port
    zot_port=$(cat "${BATS_FILE_TMPDIR}/zot.port")
    local log_file="${BATS_FILE_TMPDIR}/zot.log"
    local start_line
    start_line=$(( $(wc -l < "${log_file}") + 1 ))

    run skopeo --insecure-policy copy --dest-tls-verify=false \
        "oci:${TEST_DATA_DIR}/emudhra:latest" \
        "docker://127.0.0.1:${zot_port}/emudhra:latest"
    [ "${status}" -eq 0 ]

    wait_for_log_entry "${log_file}" "${start_line}" "event publish failed"
    wait_for_log_entry "${log_file}" "${start_line}" "certificate signed by unknown authority"
}

@test "upstream sync rejects a certificate signed by the eMudhra CA" {
    local zot_port
    zot_port=$(cat "${BATS_FILE_TMPDIR}/zot.port")
    local log_file="${BATS_FILE_TMPDIR}/zot.log"
    local start_line
    start_line=$(( $(wc -l < "${log_file}") + 1 ))

    local status_code
    status_code=$(curl --silent --show-error --output /dev/null --write-out "%{http_code}" \
        --header "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
        "http://127.0.0.1:${zot_port}/v2/upstream-emudhra/manifests/latest")
    [ "${status_code}" = "503" ]

    wait_for_log_entry "${log_file}" "${start_line}" "on-demand image sync failed"
    wait_for_log_entry "${log_file}" "${start_line}" "certificate signed by unknown authority"
}
