function add_test_files() {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    echo ${zot_root_dir}
    cp -r ${TEST_DATA_DIR}/golang ${zot_root_dir}
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
