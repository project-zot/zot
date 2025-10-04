ROOT_DIR=$(git rev-parse --show-toplevel)
OS=$(go env GOOS)
ARCH=$(go env GOARCH)
ZOT_PATH=${ROOT_DIR}/bin/zot-${OS}-${ARCH}
ZLI_PATH=${ROOT_DIR}/bin/zli-${OS}-${ARCH}
ZOT_MINIMAL_PATH=${ROOT_DIR}/bin/zot-${OS}-${ARCH}-minimal

# basic auth
ZOT_AUTH_USER=poweruser
ZOT_AUTH_PASS=sup*rSecr9T
ZOT_CREDS_PATH="${BATS_FILE_TMPDIR}/creds"
ZOT_HTPASSWD_PATH="${ZOT_CREDS_PATH}/htpasswd"

# zb
ZB_PATH=${ROOT_DIR}/bin/zb-${OS}-${ARCH}
ZB_RESULTS_PATH=${ROOT_DIR}/zb-results
ZB_CI_CD_OUTPUT_FILE=${ROOT_DIR}/ci-cd.json

# zot scale out cluster
ZOT_CLUSTER_MEMBERS_PATCH_FILE="${BATS_FILE_TMPDIR}/members-patch.json"
ZOT_ROOT_DIR="${BATS_FILE_TMPDIR}/zot"
ZOT_TLS_CERT_PATH="${ROOT_DIR}/test/data/server.cert"
ZOT_TLS_KEY_PATH="${ROOT_DIR}/test/data/server.key"
ZOT_TLS_CA_CERT_PATH="${ROOT_DIR}/test/data/ca.crt"

function verify_prerequisites {
    if [ ! -f ${ZOT_PATH} ]; then
        echo "you need to build ${ZOT_PATH} before running the tests" >&3
        return 1
    fi

    if [ ! -f ${ZB_PATH} ]; then
        echo "you need to build ${ZB_PATH} before running the tests" >&3
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

    if [ ! $(command -v haproxy) ] &>/dev/null; then
        echo "you need to install haproxy as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function zot_serve() {
    local config_file=${1}
    ${ZOT_PATH} serve ${config_file} &
}

# stops all zot instances started by the test
function zot_stop_all() {
    pkill zot
}

# waits for the zot server to be reachable
# leaving argument 2 blank or specifying "http" causes the function to use HTTP
# specifying "https" for argument 2 causes the function to use TLS
function wait_zot_reachable() {
    local zot_port=${1}
    local protocol=${2}
    if [ -z "${protocol}" ]; then
        protocol="http"
    fi

    local zot_url="${protocol}://127.0.0.1:${zot_port}/v2/_catalog"

    local curl_opts=(
        --connect-timeout 3
        --max-time 5
        --retry 20
        --retry-delay 1
        --retry-max-time 180
        --retry-connrefused
    )

    # since this is only a reachability check, we can disable cert verification
    if [ "${protocol}" == "https" ]; then
        curl_opts=(--insecure "${curl_opts[@]}")
    fi

    curl "${curl_opts[@]}" ${zot_url}
}

function zb_run() {
    local test_name=${1}
    local zot_address=${2}
    local concurrent_reqs=${3}
    local num_requests=${4}
    local credentials=${5}

    if [ ! -d "${ZB_RESULTS_PATH}" ]; then
        mkdir -p "${ZB_RESULTS_PATH}"
    fi

    local zb_args=(
        -c ${concurrent_reqs}
        -n ${num_requests}
        --src-cidr 127.0.10.0/24
        -o ci-cd
        --skip-cleanup
    )

    if [ ! -z "${credentials}" ]; then
        zb_args=(-A ${credentials} "${zb_args[@]}")
    fi

    start=$(date +%s)
    ${ZB_PATH} "${zb_args[@]}" ${zot_address}
    stop=$(date +%s)

    runtime=$((stop-start))
    echo "Duration: ${runtime} seconds" >&3

    if [ -f "${ZB_CI_CD_OUTPUT_FILE}" ]; then
        mv "${ZB_CI_CD_OUTPUT_FILE}" "${ZB_RESULTS_PATH}/${test_name}-results.json"
    fi
}

function setup_local_htpasswd() {
    create_htpasswd_file "${ZOT_CREDS_PATH}" "${ZOT_HTPASSWD_PATH}" ${ZOT_AUTH_USER} ${ZOT_AUTH_PASS}
}

function create_htpasswd_file() {
    local creds_dir_path="${1}"
    local htpasswd_file_path="${2}"
    local user=${3}
    local password=${4}

    mkdir -p "${creds_dir_path}"
    htpasswd -b -c -B "${htpasswd_file_path}" ${user} ${password}
}

# given the number of zot instances, computes a list of cluster members
# and saves them as a JSON to a file that can be used with jq later.
function generate_zot_cluster_member_list() {
    local num_zot_instances=${1}
    shift
    local patch_file_path=${1}
    shift
    local zot_ports=("$@")
    local temp_file="${BATS_FILE_TMPDIR}/jq-member-dump.json"
    echo "{\"cluster\":{\"members\":[]}}" > ${patch_file_path}

    for inst in "${zot_ports[@]}"; do
        local member="127.0.0.1:${inst}"
        jq ".cluster.members += [\"${member}\"]" ${patch_file_path} > ${temp_file} && \
        mv ${temp_file} ${patch_file_path}
    done

    echo "cluster members patch file" >&3
    cat ${patch_file_path} >&3
}

# patches an existing zot config file to add all the cluster members.
function update_zot_cluster_member_list_in_config_file() {
    local zot_config_file=${1}
    local zot_members_patch_file=${2}
    local temp_file="${BATS_FILE_TMPDIR}/jq-mem-update-dump.json"

    jq -s '.[0] * .[1]' ${zot_config_file} ${zot_members_patch_file} > ${temp_file} && \
    mv ${temp_file} ${zot_config_file}
}

# generates and saves a base cloud config with shared storage
# given some basic parameters about the zot instance.
function create_zot_cloud_base_config_file() {
    local zot_server_address=${1}
    local zot_server_port=${2}
    local zot_root_dir="${3}"
    local zot_config_file="${4}"
    local zot_log_file="${5}"

    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}",
        "dedupe": false,
        "remoteCache": true,
        "storageDriver": {
            "name": "s3",
            "rootdirectory": "/zot",
            "region": "us-east-2",
            "regionendpoint": "localhost:4566",
            "bucket": "zot-storage-test",
            "secure": false,
            "skipverify": false
        },
        "cacheDriver": {
            "name": "dynamodb",
            "endpoint": "http://localhost:4566",
            "region": "us-east-2",
            "cacheTablename": "BlobTable",
            "repoMetaTablename": "RepoMetadataTable",
            "imageMetaTablename": "ImageMetaTable",
            "repoBlobsInfoTablename": "RepoBlobsInfoTable",
            "userDataTablename": "UserDataTable",
            "apiKeyTablename":"ApiKeyTable",
            "versionTablename": "Version"
        }
    },
    "http": {
        "address": "${zot_server_address}",
        "port": "${zot_server_port}",
        "realm": "zot"
    },
    "cluster": {
      "members": [],
      "hashKey": "loremipsumdolors"
    },
    "log": {
        "level": "debug",
        "output": "${zot_log_file}"
    }
}
EOF
}

# generates and saves a cloud config with Redis cache and shared storage
# given some basic parameters about the zot instance.
function create_zot_cloud_redis_config_file() {
    local zot_server_address=${1}
    local zot_server_port=${2}
    local zot_root_dir=${3}
    local zot_config_file=${4}
    local zot_log_file=${5}
    local redis_url=${6}

    cat > ${zot_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}",
        "dedupe": true,
        "remoteCache": true,
        "storageDriver": {
            "name": "s3",
            "rootdirectory": "/zot",
            "region": "us-east-2",
            "regionendpoint": "localhost:4566",
            "bucket": "zot-storage-test",
            "secure": false,
            "skipverify": false
        },
        "cacheDriver": {
            "name": "redis",
            "url": "${redis_url}"
        }
    },
    "http": {
        "address": "${zot_server_address}",
        "port": "${zot_server_port}"
    },
    "log": {
        "level": "debug",
        "output": "${zot_log_file}"
    },
    "extensions": {
      "ui": {
        "enable": true
      },
      "search": {
        "enable": true
      }
    }
}
EOF
}

# updates an existing zot config file that already has an HTTP config
# to include htpasswd auth settings.
# intended for use with create_zot_cloud_base_config_file() above.
function update_zot_cfg_set_htpasswd_auth() {
    local zot_config_file="${1}"
    local zot_htpasswd_path="${2}"
    local temp_file="${BATS_FILE_TMPDIR}/jq-auth-dump.json"

    # set zot htpasswd auth
    jq --arg htpasswd_path "${zot_htpasswd_path}" \
        '(.http) += {auth: {htpasswd: {path: $htpasswd_path}}}' \
        ${zot_config_file} > ${temp_file} && \
    mv ${temp_file} ${zot_config_file}
}

# updates an existing zot config file that already has an HTTP config
# to include TLS configuration.
# intended for use with create_zot_cloud_base_config_file() above.
function update_zot_cfg_set_tls() {
    local zot_config_file="${1}"
    local zot_cert_path="${2}"
    local zot_key_path="${3}"
    local zot_cacert_path="${4}"
    local temp_file="${BATS_FILE_TMPDIR}/jq-tls-dump.json"

    # set zot TLS config
    jq --arg zot_cert_path "${zot_cert_path}" --arg zot_key_path "${zot_key_path}" '(.http) += {tls: {cert: $zot_cert_path, key: $zot_key_path}}' \
        ${zot_config_file} > ${temp_file} && \
    mv ${temp_file} ${zot_config_file}

    jq --arg zot_cacert_path "${zot_cacert_path}" '(.cluster) += {tls: {cacert: $zot_cacert_path}}' \
        ${zot_config_file} > ${temp_file} && \
    mv ${temp_file} ${zot_config_file}
}
