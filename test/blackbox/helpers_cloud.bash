ROOT_DIR=$(git rev-parse --show-toplevel)
TEST_DATA_DIR=${ROOT_DIR}/test/data
OS="${OS:-linux}"
ARCH="${ARCH:-amd64}"
ZOT_PATH=${ROOT_DIR}/bin/zot-${OS}-${ARCH}

mkdir -p ${TEST_DATA_DIR}

function verify_prerequisites {
    if [ ! -f ${ZOT_PATH} ]; then
        echo "you need to build ${ZOT_PATH} before running the tests" >&3
        return 1
    fi

    if [ ! $(command -v skopeo) ]; then
        echo "you need to install skopeo as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v awslocal) ] &>/dev/null; then
        echo "you need to install aws cli as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function zot_serve_strace() {
    local config_file=${1}
    strace -o "strace.txt" -f -e trace=openat ${ZOT_PATH} serve ${config_file} &
}

function zot_serve() {
    local config_file=${1}
    ${ZOT_PATH} serve ${config_file} &
}

function zot_stop() {
    pkill zot
}

function wait_zot_reachable() {
    local zot_port=${1}
    local zot_url=http://127.0.0.1:${zot_port}/v2/_catalog
    curl --connect-timeout 3 \
        --max-time 10 \
        --retry 10 \
        --retry-delay 0 \
        --retry-max-time 120 \
        --retry-connrefused \
        ${zot_url}
}
