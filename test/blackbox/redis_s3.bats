# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_redis
load helpers_cloud

function verify_prerequisites() {
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
    redis_port=$(get_free_port)
    redis_start redis_server ${redis_port}

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
        "dedupe": true,
        "gc": true,
        "rootDirectory": "${zot_root_dir}",
        "cacheDriver": {
            "name": "redis",
            "rootDir": "${zot_root_dir}/_redis",
            "url": "redis://localhost:${redis_port}"
        },
        "storageDriver": {
            "name": "s3",
            "rootdirectory": "/zot",
            "region": "us-east-2",
            "regionendpoint": "localhost:4566",
            "bucket": "zot-storage",
            "secure": false,
            "skipverify": false
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

    awslocal s3 ls s3://zot-storage || awslocal s3 --region "us-east-2" mb s3://zot-storage

    zot_serve ${ZOT_PATH} ${zot_sync_ondemand_config_file}
    wait_zot_reachable ${zot_port}
}

@test "push 3 images with dedupe enabled" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`

    for i in {1..3}
    do
        run skopeo --insecure-policy copy --dest-tls-verify=false \
            oci:${TEST_DATA_DIR}/alpine:1 \
            docker://127.0.0.1:${zot_port}/alpine${i}:1.0
        [ "$status" -eq 0 ]
    done
}

@test "pull second image with deduped blobs" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`

    run skopeo --insecure-policy copy --src-tls-verify=false docker://127.0.0.1:${zot_port}/alpine2 oci:test1/alpine2:1.0
    [ "$status" -eq 0 ]
}

@test "original blobs are moved to the next image when removing the first one" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`

    # in case of s3, because it doesn't support symlinks:
    # blobs contents are stored only once, the rest of deduped blobs are 0 size files
    # when removing an image which contains original blobs, their contents should move to the next candidates.
    # so removing the first image: alpine1 which contains only original blobs, the contents should move to alpine2
    run skopeo --insecure-policy delete --tls-verify=false \
        docker://127.0.0.1:${zot_port}/alpine1:1.0
    [ "$status" -eq 0 ]

    # pulling the next image should work
    run skopeo --insecure-policy copy --src-tls-verify=false docker://127.0.0.1:${zot_port}/alpine2 oci:test2/alpine2:1.0
    [ "$status" -eq 0 ]
}

function teardown_file() {
    zot_stop_all
    redis_stop redis_server
}
