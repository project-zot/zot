# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_events

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
}

function setup_file() {
    # verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi
}

@test "startup error when invalid sink is specified" {
    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    mkdir -p ${zot_root_dir}
    zot_port=$(get_free_port)
    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}"
    },
    "log": {
        "level": "debug",
        "output": "${BATS_FILE_TMPDIR}/zot.log"
    },
    "extensions": {
        "events": {
            "enable": true,
            "sinks": [
                {
                    "type": "http",
                    "address": "http://127.0.0.1:${http_server_port}/events",
                    "timeout": "15s",
                    "credentials": {
                        "username": "jane.joe",
                        "password": "opensesame"
                    }
                },
                {
                    "type": "generic",
                    "address": "http://127.0.0.1:${http_server_port}/events",
                    "timeout": "15s",
                    "credentials": {
                        "username": "jane.joe",
                        "password": "opensesame"
                    }
                }
            ]
        }
    }
}
EOF
    run ${ZOT_PATH} verify ${zot_config_file}
    [ "$status" -ne 0 ]
    [[ "$output" =~ "event sink is not supported" ]]
}

@test "no error when valid sinks are specified" {
    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    mkdir -p ${zot_root_dir}
    zot_port=$(get_free_port)
    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}"
    },
    "log": {
        "level": "debug",
        "output": "${BATS_FILE_TMPDIR}/zot.log"
    },
    "extensions": {
        "events": {
            "enable": true,
            "sinks": [{
                "type": "http",
                "address": "http://127.0.0.1:${http_server_port}/events",
                "timeout": "15s",
                "credentials": {
                    "username": "jane.joe",
                    "password": "opensesame"
                }
            }]
        }
    }
}
EOF
    run ${ZOT_PATH} verify ${zot_config_file}
    [ "$status" -eq 0 ]
}