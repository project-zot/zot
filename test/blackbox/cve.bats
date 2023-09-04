# Note: Intended to be run as "make test-bats-cve" or "make test-bats-cve-verbose"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot

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
    export REGISTRY_NAME=main
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
    cat >${zot_config_file} <<EOF
{
    "distSpecVersion": "1.1.0-dev",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8080"
    },
    "log": {
        "level": "debug"
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
    wait_zot_reachable 8080

    # setup zli to add zot registry to configs
    local registry_name=main
    local registry_url="http://127.0.0.1:8080/"
    zli_add_config ${registry_name} ${registry_url}
}

function teardown_file() {
    zot_stop_all
}

@test "cve by image name and tag" {
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:8080/golang:1.20
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:8080/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]
    run curl http://127.0.0.1:8080/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
    run ${ZLI_PATH} cve image golang:1.20 --config ${REGISTRY_NAME}
    [ "$status" -eq 0 ]

    found=0
    for i in "${lines[@]}"
    do

        if [[ "$i" = *"CVE-2011-4915     LOW       fs/proc/base.c in the Linux kernel through 3..."* ]]; then
            found=1
        fi
    done
    [ "$found" -eq 1 ]
}
