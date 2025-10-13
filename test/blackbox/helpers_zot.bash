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

mkdir -p ${TEST_DATA_DIR}

function zot_serve() {
    local zot_path=${1}
    local config_file=${2}
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

function wait_zot_reachable() {
    local zot_port=${1}
    local zot_url=http://127.0.0.1:${zot_port}/v2/_catalog
    curl --connect-timeout 3 \
        --max-time 5 \
        --retry 60 \
        --retry-delay 1 \
        --retry-max-time 180 \
        --retry-connrefused \
        ${zot_url}
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

function zb_run() {
    local zot_address=${1}
    ${ZB_PATH} -c 10 -n 30 -o stdout ${zot_address} --skip-cleanup
}
