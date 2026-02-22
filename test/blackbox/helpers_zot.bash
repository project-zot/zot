ROOT_DIR=$(git rev-parse --show-toplevel)
OS=$(go env GOOS)
ARCH=$(go env GOARCH)
ZOT_PATH=${ROOT_DIR}/bin/zot-${OS}-${ARCH}
ZLI_PATH=${ROOT_DIR}/bin/zli-${OS}-${ARCH}
ZOT_MINIMAL_PATH=${ROOT_DIR}/bin/zot-${OS}-${ARCH}-minimal
ZB_PATH=${ROOT_DIR}/bin/zb-${OS}-${ARCH}
TEST_DATA_DIR=${BATS_FILE_TMPDIR}/test/data
AUTH_USER=poweruser
AUTH_PASS=sup*rSecr9T
# additional creds for sha256/sha512 based password hashes
AUTH_USER2=poweruser2
AUTH_PASS2=sup*rSecr2T
AUTH_USER3=poweruser3
AUTH_PASS3=sup*rSecr3T
AUTH_USER4=poweruser4
AUTH_PASS4=sup*rSecr4T
AUTH_USER5=poweruser5
AUTH_PASS5=sup*rSecr5T

mkdir -p ${TEST_DATA_DIR}

function zot_serve() {
    local zot_path=${1}
    local config_file=${2}
    ${zot_path} serve ${config_file} &
    # zot.pid file keeps a list of zot server PIDs (in case multiple zot servers are started)
    echo -n "$! " >> ${BATS_FILE_TMPDIR}/zot.pid
}

function zot_rel_serve() {
    local config_file=${1}
    local zot_path=${BATS_FILE_TMPDIR}/zot-rel-${OS}-${ARCH}

    if [ ! -f "${zot_path}" ]; then
        if ! curl -f -L -o "${zot_path}" https://github.com/project-zot/zot/releases/latest/download/zot-${OS}-${ARCH}; then 
            echo "ERROR: Failed to download zot binary from GitHub." >&2
            return 1
        fi
        # Download checksum file and verify integrity
        checksum_url="https://github.com/project-zot/zot/releases/latest/download/checksums.sha256.txt"
        checksum_file="${BATS_FILE_TMPDIR}/zot-sha256sums.txt"
        curl -L -o "${checksum_file}" "${checksum_url}"
        expected_sum=$(grep "zot-${OS}-${ARCH}$" "${checksum_file}" | awk '{print $1}')
        if [ -z "${expected_sum}" ]; then
            echo "ERROR: Could not find checksum for zot-${OS}-${ARCH} in checksums.sha256.txt"
            exit 1
        fi
        actual_sum=$(sha256sum "${zot_path}" | awk '{print $1}')
        if [ "${expected_sum}" != "${actual_sum}" ]; then
            echo "ERROR: Checksum verification failed for zot-${OS}-${ARCH}"
            exit 1
        fi
        chmod +x "${zot_path}"
    fi

    ${zot_path} serve ${config_file} &
    # zot.pid file keeps a list of zot server PIDs (in case multiple zot servers are started)
    echo -n "$! " >> ${BATS_FILE_TMPDIR}/zot.pid
}

function zot_rel_min_serve() {
    local config_file=${1}
    local zot_path=${BATS_FILE_TMPDIR}/zot-rel-${OS}-${ARCH}-minimal

    if [ ! -f "${zot_path}" ]; then
        if ! curl -f -L -o "${zot_path}" https://github.com/project-zot/zot/releases/latest/download/zot-${OS}-${ARCH}-minimal; then
            echo "ERROR: Failed to download zot binary from GitHub." >&2
            return 1
        fi
        # Download checksum file and verify integrity
        checksum_url="https://github.com/project-zot/zot/releases/latest/download/checksums.sha256.txt"
        checksum_file="${BATS_FILE_TMPDIR}/zot-sha256sums.txt"
        curl -L -o "${checksum_file}" "${checksum_url}"
        expected_sum=$(grep "zot-${OS}-${ARCH}-minimal$" "${checksum_file}" | awk '{print $1}')
        if [ -z "${expected_sum}" ]; then
            echo "ERROR: Could not find checksum for zot-${OS}-${ARCH}-minimal in checksums.sha256.txt"
            exit 1
        fi
        actual_sum=$(sha256sum "${zot_path}" | awk '{print $1}')
        if [ "${expected_sum}" != "${actual_sum}" ]; then
            echo "ERROR: Checksum verification failed for zot-${OS}-${ARCH}-minimal"
            exit 1
        fi
        chmod +x "${zot_path}"
    fi

    ${zot_path} serve ${config_file} &
    # zot.pid file keeps a list of zot server PIDs (in case multiple zot servers are started)
    echo -n "$! " >> ${BATS_FILE_TMPDIR}/zot.pid
}

# stops all zot instances started by the test
function zot_stop_all() {
    if [ -f "${BATS_FILE_TMPDIR}/zot.pid" ]; then
        kill $(cat ${BATS_FILE_TMPDIR}/zot.pid) 2>/dev/null || true
        rm -f ${BATS_FILE_TMPDIR}/zot.pid
    fi
}

# Verifies zot is listening and responding with a valid /v2/_catalog.
# Exits with 1 and a clear message if zot did not start or response is not from zot.
function wait_zot_reachable() {
    local zot_port=${1}
    local zot_url=http://127.0.0.1:${zot_port}/v2/_catalog

    # If we have zot PIDs, ensure at least one process is still running (zot didn't exit on startup, e.g. bind failure).
    # When multiple zots run in the same test (e.g. sync.bats), zot.pid holds all PIDs; we only require one alive here.
    # The curl below to the given port is what confirms the specific instance for that port is up.
    if [ -f "${BATS_FILE_TMPDIR}/zot.pid" ]; then
        local pids
        read -r pids < "${BATS_FILE_TMPDIR}/zot.pid" || true
        local one_alive=0
        for p in $pids; do
            kill -0 "$p" 2>/dev/null && one_alive=1 && break
        done
        if [ "$one_alive" -eq 0 ]; then
            echo "ERROR: zot process(es) exited before becoming reachable (check bind or config). Port ${zot_port}" >&2
            exit 1
        fi
    fi

    local response
    response=$(curl -s --connect-timeout 3 \
        --max-time 5 \
        --retry 60 \
        --retry-delay 1 \
        --retry-max-time 180 \
        --retry-connrefused \
        -w "\n%{http_code}" \
        "${zot_url}")
    local curl_ret=$?
    if [ $curl_ret -ne 0 ]; then
        echo "ERROR: zot did not become reachable at ${zot_url}" >&2
        exit 1
    fi

    # curl -s -w "\n%{http_code}" appends HTTP code on last line; body is everything else
    local http_code
    http_code=$(echo "$response" | tail -n1)
    response=$(echo "$response" | sed '$d')

    if [ "$http_code" = "401" ]; then
        # Zot is up but requires auth (e.g. redis_session_store, openid_claim_mapping); treat as reachable
        echo "$response"
        return 0
    fi

    if [ "$http_code" != "200" ]; then
        echo "ERROR: zot at ${zot_url} returned HTTP ${http_code}" >&2
        exit 1
    fi

    if ! echo "$response" | jq -e '.repositories != null' >/dev/null 2>&1; then
        echo "ERROR: response from ${zot_url} is not a valid zot _catalog response (missing .repositories)" >&2
        exit 1
    fi
    echo "$response"
}

function zli_add_config() {
    local registry_name=${1}
    local registry_url=${2}
    # Clean up old configuration for the same registry
    if ${ZLI_PATH} config --list | grep -q ${registry_name}; then
        ${ZLI_PATH} config remove ${registry_name}
    fi
    # Add the new registry
    ${ZLI_PATH} config add ${registry_name} ${registry_url}
}

function zli_show_config() {
    local registry_name=${1}
    ${ZLI_PATH} config ${registry_name} -l || true
}

function zli_delete_config() {
    local registry_name=${1}
    ${ZLI_PATH} config remove ${registry_name} || true
}

function zb_run() {
    local zot_address=${1}
    ${ZB_PATH} -c 10 -n 30 -o stdout ${zot_address} --skip-cleanup
}

function log_output() {
    local zot_log_file=${1:-${BATS_FILE_TMPDIR}/zot/zot-log.json}
    cat ${zot_log_file} | jq ' .["message"] '
}
