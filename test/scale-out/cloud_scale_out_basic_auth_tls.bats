# note: intended to be run as "make run-cloud-scale-out-tests".
#       makefile target installs & checks all necessary tooling
#       extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

NUM_ZOT_INSTANCES=6
ZOT_LOG_DIR=/tmp/zot-ft-logs/auth-tls

load helpers_zot
load helpers_cloud
load helpers_haproxy
load ../port_helper

function launch_zot_server() {
    local zot_server_address=${1}
    local zot_server_port=${2}
    local zot_root_dir=${ZOT_ROOT_DIR}

    mkdir -p ${zot_root_dir}
    mkdir -p ${ZOT_LOG_DIR}

    local zot_config_file="${BATS_FILE_TMPDIR}/zot_config_${zot_server_address}_${zot_server_port}.json"
    local zot_log_file="${ZOT_LOG_DIR}/zot-${zot_server_address}-${zot_server_port}.log"

    create_zot_cloud_base_config_file ${zot_server_address} ${zot_server_port} ${zot_root_dir} ${zot_config_file} ${zot_log_file}
    update_zot_cluster_member_list_in_config_file ${zot_config_file} ${ZOT_CLUSTER_MEMBERS_PATCH_FILE}
    
    update_zot_cfg_set_htpasswd_auth "${zot_config_file}" ${ZOT_HTPASSWD_PATH}
    update_zot_cfg_set_tls "${zot_config_file}" ${ZOT_TLS_CERT_PATH} ${ZOT_TLS_KEY_PATH} ${ZOT_TLS_CA_CERT_PATH}
 
    echo "launching zot server ${zot_server_address}:${zot_server_port}" >&3
    echo "config file: ${zot_config_file}" >&3
    echo "log file: ${zot_log_file}" >&3

    zot_serve ${zot_config_file}
    wait_zot_reachable ${zot_server_port} "https"
}

function setup() {
    # verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # setup S3 bucket and DynamoDB tables
    setup_cloud_services
    # setup htpasswd for local auth
    setup_local_htpasswd

    # generate the free ports list
    zot_srv_ports=()
    for ((i=0;i<${NUM_ZOT_INSTANCES};i++)); do
        port=$(get_free_port_for_service "zot${i}")
        zot_srv_ports+=("${port}")
    done

    generate_zot_cluster_member_list ${NUM_ZOT_INSTANCES} ${ZOT_CLUSTER_MEMBERS_PATCH_FILE} "${zot_srv_ports[@]}"

    for inst in "${zot_srv_ports[@]}"; do
        launch_zot_server 127.0.0.1 ${inst}
    done

    # list all zot processes that were started
    ps -ef | grep ".*zot.*serve.*" | grep -v grep >&3

    haproxy_port=$(get_free_port_for_service "haproxy")
    echo ${haproxy_port} > ${BATS_FILE_TMPDIR}/haproxy.port

    generate_haproxy_config ${HAPROXY_CFG_FILE} "https" ${haproxy_port} "${zot_srv_ports[@]}"
    haproxy_start ${HAPROXY_CFG_FILE}

    # list haproxy processes that were started
    ps -ef | grep "haproxy" | grep -v grep >&3
}

function teardown() {
    local zot_root_dir=${ZOT_ROOT_DIR}
    haproxy_stop_all
    zot_stop_all
    rm -rf ${zot_root_dir}
    teardown_cloud_services
}

@test "Check for successful zb run on haproxy frontend" {
    haproxy_port=`cat ${BATS_FILE_TMPDIR}/haproxy.port`

    # zb_run <test_name> <zot_address> <concurrency> <num_requests> <credentials (optional)>
    zb_run "cloud-scale-out-basic-auth-tls-bats" "https://127.0.0.1:${haproxy_port}" 3 5 "${ZOT_AUTH_USER}:${ZOT_AUTH_PASS}"
}
