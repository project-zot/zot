ROOT_DIR=$(git rev-parse --show-toplevel)
TEST_DATA_DIR=${ROOT_DIR}/test/data/
OS="${OS:-linux}"
ARCH="${ARCH:-amd64}"
ZOT_PATH=${ROOT_DIR}/bin/zot-${OS}-${ARCH}

ZOT_MINIMAL_PATH=${ROOT_DIR}/bin/zot-${OS}-${ARCH}-minimal
ZB_PATH=${ROOT_DIR}/bin/zb-${OS}-${ARCH}

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

    if [ ! -f ${ZB_PATH} ]; then
        echo "you need to build ${ZB_PATH} before running the tests" >&3
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

function zb_run() {
    local zot_address=${1}
    ${ZB_PATH} -c 10 -n 30 -o stdout ${zot_address} --skip-cleanup
}

function wait_str() {
    local filepath="$1"
    local search_term="$2"
    local wait_time="${3:-2m}"

    (timeout $wait_time tail -F -n0 "$filepath" &) | grep -q "$search_term" && return 0

    echo "timeout of $wait_time reached. unable to find '$search_term' in '$filepath'"
    
    return 1
}

function wait_for_string() {
    local search_term="$1"
    local filepath="$2"
    local wait_time="${3:-2m}"

    wait_file "$filepath" 60 || { echo "server log file missing: '$filepath'"; return 1; }

    wait_str "$filepath" "$search_term" "$wait_time"
}

function wait_file() {
    local file="$1"; shift
    local wait_seconds="${1:-60}"; shift

    until test $((wait_seconds--)) -eq 0 -o -f "$file" ; do sleep 1; done
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
