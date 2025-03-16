# note: intended to be run as "make run-cloud-scale-out-redis-high-scale-tests"
#       makefile target installs & checks all necessary tooling
#       extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

NUM_ZOT_INSTANCES=6
ZOT_LOG_DIR=/tmp/zot-ft-logs/redis-scale

load helpers_zot
load helpers_cloud
load helpers_haproxy
load helpers_redis

function verify_prerequisites() {
    if [ ! $(command -v docker) ]; then
        echo "you need to install docker as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function launch_zot_server() {
    local zot_server_address=${1}
    local zot_server_port=${2}
    local zot_root_dir=${ZOT_ROOT_DIR}
    local redis_url=${3}

    mkdir -p ${zot_root_dir}
    mkdir -p ${ZOT_LOG_DIR}

    local zot_config_file="${BATS_FILE_TMPDIR}/zot_config_${zot_server_address}_${zot_server_port}.json"
    local zot_log_file="${ZOT_LOG_DIR}/zot-${zot_server_address}-${zot_server_port}.log"

    create_zot_cloud_redis_config_file ${zot_server_address} ${zot_server_port} ${zot_root_dir} ${zot_config_file} ${zot_log_file} ${redis_url}
    update_zot_cluster_member_list_in_config_file ${zot_config_file} ${ZOT_CLUSTER_MEMBERS_PATCH_FILE}
    
    echo "launching zot server ${zot_server_address}:${zot_server_port}" >&3
    echo "config file: ${zot_config_file}" >&3
    echo "log file: ${zot_log_file}" >&3

    zot_serve ${zot_config_file}
    wait_zot_reachable ${zot_server_port}
}

function setup() {
    # verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # setup Redis server
    redis_port=$(get_free_port)
    redis_start redis_server ${redis_port}
    local redis_url="redis://127.0.0.1:${redis_port}"
    
    # setup S3 bucket and DynamoDB tables
    setup_cloud_services
    generate_zot_cluster_member_list ${NUM_ZOT_INSTANCES} ${ZOT_CLUSTER_MEMBERS_PATCH_FILE}

    for ((i=0;i<${NUM_ZOT_INSTANCES};i++)); do
        launch_zot_server 127.0.0.1 $(( 10000 + $i )) ${redis_url}
    done

    # list all zot processes that were started
    ps -ef | grep ".*zot.*serve.*" | grep -v grep >&3

    generate_haproxy_config ${HAPROXY_CFG_FILE} "http"
    haproxy_start ${HAPROXY_CFG_FILE}

    # list HAproxy processes that were started
    ps -ef | grep "haproxy" | grep -v grep >&3
}

function teardown() {
    local zot_root_dir=${ZOT_ROOT_DIR}
    haproxy_stop_all
    zot_stop_all
    redis_stop redis_server
    rm -rf ${zot_root_dir}
    teardown_cloud_services
}

@test "Check for successful zb run on haproxy frontend with Redis cache (high scale)" {
    # zb_run <test_name> <zot_address> <concurrency> <num_requests> <credentials (optional)>
    zb_run "cloud-scale-out-redis-scale-bats" "http://127.0.0.1:8000" 10 100
} 