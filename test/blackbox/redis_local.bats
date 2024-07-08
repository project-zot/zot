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

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20

    # Setup redis server
    redis_port=$(get_free_port)
    redis_start redis_server_local ${redis_port}

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
            "url": "redis://localhost:${redis_port}"
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
      },
      "search": {
        "enable": true
      }
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_sync_ondemand_config_file}
    wait_zot_reachable ${zot_port}
}

@test "push 2 images" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 0 ]

    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/golang2:1.20
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[0]') = '"golang"' ]
    [ $(echo "${lines[-1]}" | jq '.repositories[1]') = '"golang2"' ]
    run curl http://127.0.0.1:${zot_port}/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
}

@test "pull both images" {
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`

    mkdir -p ${oci_data_dir}
    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:${zot_port}/golang:1.20 \
        oci:${oci_data_dir}/golang:1.20
    [ "$status" -eq 0 ]
    run cat ${BATS_FILE_TMPDIR}/oci/golang/index.json
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].annotations."org.opencontainers.image.ref.name"') = '"1.20"' ]

    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:${zot_port}/golang2:1.20 \
        oci:${oci_data_dir}/golang:1.20
    [ "$status" -eq 0 ]
}

function teardown_file() {
    zot_stop_all
    redis_stop redis_server_local
}
