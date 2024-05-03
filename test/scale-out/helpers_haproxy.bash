HAPROXY_CFG_FILE="${BATS_FILE_TMPDIR}/haproxy/haproxy-test.cfg"

function generate_haproxy_server_list() {
    local num_instances=${1}
    for ((i=0;i<${num_instances};i++)) do
        local port=$(( 10000 + $i ))
        echo "    server zot${i} 127.0.0.1:${port}"
    done
}

# stops all haproxy instances started by the test
function haproxy_stop_all() {
    pkill haproxy
}

# starts one haproxy instance with the given config file
# expects the haproxy config to specify daemon mode
function haproxy_start() {
    local haproxy_cfg_file=${1}

    # Check the config file
    haproxy -f ${haproxy_cfg_file} -c >&3

    # Start haproxy
    haproxy -f ${haproxy_cfg_file}
}

# generates HAproxy config for use in the test
function generate_haproxy_config() {
    local haproxy_cfg_file="${1}"
    local haproxy_root_dir="$(dirname ${haproxy_cfg_file})"
    # can be either http or https
    local protocol="${2}"

    mkdir -p ${haproxy_root_dir}

    local haproxy_mode='http'
    if [ "$protocol" == 'https' ]; then
        haproxy_mode='tcp'
    fi

    cat > ${haproxy_cfg_file}<<EOF
global
    log ${haproxy_root_dir}/log local0
    log ${haproxy_root_dir}/log local1 notice
    maxconn 20000
    stats timeout 30s
    daemon

defaults
    log     global
    mode    ${haproxy_mode}
    option  ${haproxy_mode}log
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000

frontend zot
    bind *:8000
    default_backend zot-cluster

backend zot-cluster
    balance roundrobin
EOF

    # Populate server list
    generate_haproxy_server_list ${NUM_ZOT_INSTANCES} >> ${haproxy_cfg_file}

    cat ${haproxy_cfg_file} >&3
}
