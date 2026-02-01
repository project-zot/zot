# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load ../port_helper

function verify_prerequisites {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v jq) ]; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function setup_file() {
    # Use unique config name based on test file name and test run to avoid conflicts
    export REGISTRY_NAME=$(basename "${BASH_SOURCE[0]}" .bats)-$(basename "${BATS_FILE_TMPDIR}")
    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20
    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    mkdir -p ${zot_root_dir}
    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    cat >${zot_config_file} <<EOF
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
        "search": {
            "enable": true,
            "cve": {
                "updateInterval": "24h"
            }
        }
    }
}
EOF
    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}

    # setup zli to add zot registry to configs
    local registry_url="http://127.0.0.1:${zot_port}/"
    zli_add_config ${REGISTRY_NAME} ${registry_url}
}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot.log
    # Show zli config for debugging
    zli_show_config ${REGISTRY_NAME}
}

function teardown_file() {
    zot_stop_all
    # Clean up zli config
    zli_delete_config ${REGISTRY_NAME}
}

@test "cve by image name and tag" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]
    run curl http://127.0.0.1:${zot_port}/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
    sleep 10     # wait a little to populate metadb
    run ${ZLI_PATH} cve list golang:1.20 --config ${REGISTRY_NAME}
    [ "$status" -eq 0 ]

    echo ${lines[@]}

    found=0
    for i in "${lines[@]}"
    do

        if [[ "$i" = *"CVE-2011-4915    LOW      fs/proc/base.c in the Linux kernel through 3..."* ]]; then
            found=1
        fi
    done
    [ "$found" -eq 1 ]
}
