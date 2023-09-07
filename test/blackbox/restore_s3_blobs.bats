# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-dedupe-nightly"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_cloud
load helpers_wait

function setup_file() {
    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20
    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file_dedupe=${BATS_FILE_TMPDIR}/zot_config_dedupe.json
    local zot_config_file_nodedupe=${BATS_FILE_TMPDIR}/zot_config_nodedupe.json
    local ZOT_LOG_FILE=${zot_root_dir}/zot-log.json
    mkdir -p ${zot_root_dir}

    cat > ${zot_config_file_dedupe}<<EOF
{
	"distSpecVersion": "1.1.0-dev",
	"storage": {
        "rootDirectory": "${zot_root_dir}",
        "dedupe": true,
        "remoteCache": true,
        "storageDriver": {
            "name": "s3",
            "rootdirectory": "/zot",
            "region": "us-east-2",
            "regionendpoint": "localhost:4566",
            "bucket": "zot-storage",
            "secure": false,
            "skipverify": false
        },
        "cacheDriver": {
            "name": "dynamodb",
            "endpoint": "http://localhost:4566",
            "region": "us-east-2",
            "cacheTablename": "BlobTable"
        }
	},
	"http": {
		"address": "127.0.0.1",
		"port": "8080"
	},
	"log": {
		"level": "debug"
	}
}
EOF

    cat > ${zot_config_file_nodedupe}<<EOF
{
	"distSpecVersion": "1.1.0-dev",
	"storage": {
        "rootDirectory": "${zot_root_dir}",
        "dedupe": false,
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
		"address": "127.0.0.1",
		"port": "8080"
	},
	"log": {
		"level": "debug",
        "output": "${ZOT_LOG_FILE}"
	}
}
EOF
    awslocal s3 --region "us-east-2" mb s3://zot-storage
    awslocal dynamodb --region "us-east-2" create-table --table-name "BlobTable" --attribute-definitions AttributeName=Digest,AttributeType=S --key-schema AttributeName=Digest,KeyType=HASH --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=5
    zot_serve ${zot_config_file_dedupe}
    wait_zot_reachable 8080
}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot/zot-log.json
}

function teardown_file() {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    zot_stop
    rm -rf ${zot_root_dir}
    awslocal s3 rb s3://"zot-storage" --force
    awslocal dynamodb --region "us-east-2" delete-table --table-name "BlobTable"
}

@test "push 50 images with dedupe enabled" {
    for i in {1..50}
    do
        run skopeo --insecure-policy copy --dest-tls-verify=false \
            oci:${TEST_DATA_DIR}/golang:1.20 \
            docker://127.0.0.1:8080/golang${i}:1.20
        [ "$status" -eq 0 ]
    done
}

@test "restart zot with dedupe false and wait for restore blobs task to finish" {
    local zot_config_file_nodedupe=${BATS_FILE_TMPDIR}/zot_config_nodedupe.json
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local ZOT_LOG_FILE=${zot_root_dir}/zot-log.json

    # stop server
    zot_stop

    sleep 10

    # start with dedupe disabled
    zot_serve ${zot_config_file_nodedupe}
    wait_zot_reachable 8080
    start=`date +%s`
    echo "waiting for restoring blobs task to finish" >&3
    run wait_for_string "dedupe rebuild: finished" ${ZOT_LOG_FILE} "10m"
    [ "$status" -eq 0 ]

    end=`date +%s`

    runtime=$((end-start))
    echo "restoring blobs finished in $runtime sec" >&3
    sleep 10 # wait a bit more because dedupe runs in background.
}

@test "pulling a previous deduped image should work" {
    # golang1 should have original blobs already
    echo "pulling first image" >&3
    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:8080/golang1:1.20 \
        oci:${TEST_DATA_DIR}/golang1:1.20
    [ "$status" -eq 0 ]

    echo "pulling second image" >&3
    # golang2 should have original blobs after restoring blobs
    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:8080/golang2:1.20 \
        oci:${TEST_DATA_DIR}/golang2:1.20
    [ "$status" -eq 0 ]
}


