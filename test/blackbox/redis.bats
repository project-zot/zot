# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_redis

function verify_prerequisites() {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v jq) ]; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v docker) ]; then
        echo "you need to install docker as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function setup_file() {
    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Setup redis server
    redis_start

    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_sync_ondemand_config_file=${BATS_FILE_TMPDIR}/zot_sync_ondemand_config.json
    zot_port=$(get_free_port)
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port

    mkdir -p ${zot_root_dir}

    cat >${zot_sync_ondemand_config_file} <<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${zot_root_dir}",
        "cacheDriver": {
            "name": "redis",
            "rootDir": "${zot_root_dir}/_redis",
            "url": "redis://localhost:6379"
        }
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}"
    },
    "log": {
        "level": "debug",
        "output": "/tmp/blackbox.log"
    },
    "extensions": {
      "ui": {
        "enable": true
      }
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_sync_ondemand_config_file}
    wait_zot_reachable ${zot_port}
}

function teardown_file() {
    zot_stop_all
    redis_stop
}
