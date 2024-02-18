# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot

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

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20
    # Setup zot server
    local zot_sync_one_root_dir=${BATS_FILE_TMPDIR}/zot-one
    local zot_sync_two_root_dir=${BATS_FILE_TMPDIR}/zot-two

    local zot_sync_one_config_file=${BATS_FILE_TMPDIR}/zot_sync_one_config.json
    local zot_sync_two_config_file=${BATS_FILE_TMPDIR}/zot_sync_two_config.json

    mkdir -p ${zot_sync_one_root_dir}
    mkdir -p ${zot_sync_two_root_dir}

    zot_port1=$(get_free_port)
    echo ${zot_port1} > ${BATS_FILE_TMPDIR}/zot.port1
    zot_port2=$(get_free_port)
    echo ${zot_port2} > ${BATS_FILE_TMPDIR}/zot.port2

    cat >${zot_sync_one_config_file} <<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${zot_sync_one_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port1}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_port1}",
                        "http://localhost:${zot_port2}"
                    ],
                    "onDemand": false,
                    "tlsVerify": false,
                    "PollInterval": "10s",
                    "content": [
                        {
                            "prefix": "**"
                        }
                    ]
                }
            ]
        }
    }
}
EOF

    cat >${zot_sync_two_config_file} <<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${zot_sync_two_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port2}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_port1}",
                        "http://localhost:${zot_port2}"
                    ],
                    "onDemand": false,
                    "tlsVerify": false,
                    "PollInterval": "10s",
                    "content": [
                        {
                            "prefix": "**"
                        }
                    ]
                }
            ]
        }
    }
}
EOF

    git -C ${BATS_FILE_TMPDIR} clone https://github.com/project-zot/helm-charts.git

    zot_serve ${ZOT_PATH} ${zot_sync_one_config_file}
    wait_zot_reachable ${zot_port1}

    zot_serve ${ZOT_PATH} ${zot_sync_two_config_file}
    wait_zot_reachable ${zot_port2}
}

function teardown_file() {
    zot_stop_all
}

# sync image
@test "push one image to zot one, zot two should sync it" {
    zot_port1=`cat ${BATS_FILE_TMPDIR}/zot.port1`
    zot_port2=`cat ${BATS_FILE_TMPDIR}/zot.port2`
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port1}/golang:1.20
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port1}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]
    run curl http://127.0.0.1:${zot_port1}/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]

    run sleep 30s

    run curl http://127.0.0.1:${zot_port2}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]

    run curl http://127.0.0.1:${zot_port2}/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
}

@test "push one image to zot-two, zot-one should sync it" {
    zot_port1=`cat ${BATS_FILE_TMPDIR}/zot.port1`
    zot_port2=`cat ${BATS_FILE_TMPDIR}/zot.port2`
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port2}/anothergolang:1.20
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port2}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[0]') = '"anothergolang"' ]
    run curl http://127.0.0.1:${zot_port2}/v2/anothergolang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]

    run sleep 30s

    run curl http://127.0.0.1:${zot_port1}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[0]') = '"anothergolang"' ]

    run curl http://127.0.0.1:${zot_port1}/v2/anothergolang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
}
