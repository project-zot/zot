ROOT_DIR=$(git rev-parse --show-toplevel)
TEST_DATA_DIR=${ROOT_DIR}/test/data/
OS="${OS:-linux}"
ARCH="${ARCH:-amd64}"
ZOT_PATH=${ROOT_DIR}/bin/zot-${OS}-${ARCH}
ZOT_ROOT_DIR=?
ZOT_LOG_FILE=?
ZOT_CONFIG_FILE=

function verify_prerequisites() {
    if [ ! -f ${BATS_RUN_TMPDIR}/.firstrun ]; then
        env | grep proxy >&3
        touch ${BATS_RUN_TMPDIR}/.firstrun
    fi

    if [ ! -f ${ZOT_PATH} ]; then
        echo "you need to build ${ZOT_PATH} before running tests" >&3
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

function setup_zot_file_level() {
    local config_file=${1}
    zot_serve ${ZOT_PATH} ${config_file} ${BATS_FILE_TMPDIR}
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

function add_test_files() {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    echo ${zot_root_dir}
    cp -r ${TEST_DATA_DIR}golang ${zot_root_dir}
    ls -al ${zot_root_dir}/golang
}

function delete_blob() {
    local zot_test_files=${BATS_FILE_TMPDIR}/zot/golang
    find ${zot_test_files}/blobs/sha256 -maxdepth 1 -type f -name "*" -print0 |
        sort -z -R |
        head -z -n 1 | xargs -0 rm
    ls -al ${zot_test_files}/blobs/sha256/
}

function log_output() {
    local zot_log_file=${BATS_FILE_TMPDIR}/zot/zot-log.json
    cat ${zot_log_file} | jq ' .["message"] '
}

function affected() {
    log_output | jq 'contains("blobs/manifest affected")?' | grep true
}

function not_affected() {
    log_output | jq 'contains("blobs/manifest ok")?' | grep true
}
