ROOT_DIR=$(git rev-parse --show-toplevel)
TEST_DATA_DIR=${ROOT_DIR}/test/data/
OS="${OS:-linux}"
ARCH="${ARCH:-amd64}"
ZOT_PATH=${ROOT_DIR}/bin/zot-${OS}-${ARCH}
ZOT_MINIMAL_PATH=${ROOT_DIR}/bin/zot-${OS}-${ARCH}-minimal

mkdir -p ${TEST_DATA_DIR}

function verify_prerequisites {
    if [ ! -f ${BATS_RUN_TMPDIR}/.firstrun ]; then
        env | grep proxy >&3
        touch ${BATS_RUN_TMPDIR}/.firstrun
    fi

    if [ ! -f ${ZOT_PATH} ]; then
        echo "you need to build ${ZOT_PATH} before running the tests" >&3
        return 1
    fi

    if [ ! -f ${ZOT_MINIMAL_PATH} ]; then
        echo "you need to build ${ZOT_MINIMAL_PATH} before running tests" >&3
        return 1
    fi

    if [ ! command -v curl ] &>/dev/null; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! command -v jq ] &>/dev/null; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! command -v skopeo ] &>/dev/null; then
        echo "you need to install skopeo as a prerequisite to running the tests" >&3
        return 1
    fi
    return 0
}

function zot_serve() {
    local zot_path=${1}
    local config_file=${2}
    local pid_dir=${3}
    ${zot_path} serve ${config_file} &
    echo $! >>${pid_dir}/zot.pid
}

function zot_stop() {
    local pid_dir=${1}
    cat ${pid_dir}/zot.pid
    kill $(cat ${pid_dir}/zot.pid)
    rm ${pid_dir}/zot.pid
}

function zot_minimal_stop() {
    local pid_dir=${1}
    kill $(cat ${pid_dir}/zot-minimal.pid)
    rm ${pid_dir}/zot-minimal.pid
}

function setup_zot_file_level() {
    local config_file=${1}
    zot_serve ${ZOT_PATH} ${config_file} ${BATS_FILE_TMPDIR}
}

function setup_zot_minimal_file_level() {
    local config_file=${1}
    zot_serve ${ZOT_MINIMAL_PATH} ${config_file} ${BATS_FILE_TMPDIR}
}

function teardown_zot_file_level() {
    zot_stop ${BATS_FILE_TMPDIR}
}

function wait_zot_reachable() {
    zot_url=${1}
    curl --connect-timeout 3 \
        --max-time 3 \
        --retry 10 \
        --retry-delay 0 \
        --retry-max-time 60 \
        --retry-connrefused \
        ${zot_url}
}
