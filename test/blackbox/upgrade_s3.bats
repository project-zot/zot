# Note: Intended to be run as "make run-blackbox-cloud-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()
#
# Upgrades a remote store with dedupe on from the latest release to this build. The release keeps
# each digest's content in the first repo that pushed it, with later copies as placeholders; this
# build moves the content to the global blobstore, keeps placeholders in the repos, and records
# each repo's ownership in the cache.

load helpers_zot
load ../port_helper

BUCKET=zot-storage
TABLE=BlobTable
REGION=us-east-2
S3_ROOT=zot

function verify_prerequisites() {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v jq) ]; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v skopeo) ]; then
        echo "you need to install skopeo as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v awslocal) ]; then
        echo "you need to install aws cli and awslocal as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function setup_file() {
    if ! verify_prerequisites; then
        exit 1
    fi

    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/test-images/alpine:3.17.3 \
        oci:${TEST_DATA_DIR}/alpine:3.17.3

    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    mkdir -p ${zot_root_dir}
    touch ${BATS_FILE_TMPDIR}/zot-log.json

    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port

    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}",
        "dedupe": true,
        "remoteCache": true,
        "storageDriver": {
            "name": "s3",
            "rootdirectory": "/${S3_ROOT}",
            "region": "${REGION}",
            "regionendpoint": "localhost:4566",
            "bucket": "${BUCKET}",
            "secure": false,
            "skipverify": false
        },
        "cacheDriver": {
            "name": "dynamodb",
            "endpoint": "http://localhost:4566",
            "region": "${REGION}",
            "cacheTablename": "${TABLE}"
        }
    },
    "http": {
        "address": "127.0.0.1",
        "port": "${zot_port}"
    },
    "log": {
        "level": "debug",
        "output": "${BATS_FILE_TMPDIR}/zot-log.json"
    }
}
EOF
    awslocal s3 --region "${REGION}" mb s3://${BUCKET}
    awslocal dynamodb --region "${REGION}" create-table --table-name "${TABLE}" \
        --attribute-definitions AttributeName=Digest,AttributeType=S --key-schema AttributeName=Digest,KeyType=HASH \
        --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=5

    zot_rel_serve ${zot_config_file}
    wait_zot_reachable ${zot_port}
}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot-log.json || true
}

function teardown_file() {
    zot_stop_all
    awslocal s3 rb s3://${BUCKET} --force
    awslocal dynamodb --region "${REGION}" delete-table --table-name "${TABLE}"
}

# object_size prints the size of the object holding blob digest in repo, in the bucket. S3 keys
# carry rootdirectory twice: the store's root is the driver's rootdirectory, which the driver
# prefixes again (see storage.RootDir), so blobs live under zot/zot/<repo>/.
function object_size() {
    local repo=${1}
    local digest=${2}

    awslocal s3api head-object --region "${REGION}" --bucket ${BUCKET} \
        --key "${S3_ROOT}/${S3_ROOT}/${repo}/blobs/sha256/${digest#sha256:}" --query ContentLength --output text
}

@test "[release] push the same image to two repos" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    local digests_file=${BATS_FILE_TMPDIR}/digests.txt
    : > ${digests_file}

    for repo in dup-a dup-b; do
        run skopeo --insecure-policy copy --dest-tls-verify=false \
            oci:${TEST_DATA_DIR}/alpine:3.17.3 docker://127.0.0.1:${zot_port}/${repo}:3.17.3
        [ "$status" -eq 0 ]

        local digest=$(skopeo inspect --tls-verify=false docker://127.0.0.1:${zot_port}/${repo}:3.17.3 | jq -r '.Digest')
        [ -n "${digest}" ]
        echo "${repo}=${digest}" >> ${digests_file}
    done
}

@test "[upgrade] upgrade to new binary" {
    zot_stop_all
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`

    # the upgrade runs before the server listens, so this measures it
    local start=$(date +%s)
    zot_serve ${ZOT_PATH} ${BATS_FILE_TMPDIR}/zot_config.json
    wait_zot_reachable ${zot_port}
    local end=$(date +%s)
    echo "upgrade + startup took $((end-start)) sec" >&3

    run grep -q "global blobstore upgrade completed" ${BATS_FILE_TMPDIR}/zot-log.json
    [ "$status" -eq 0 ]
}

@test "[new] the layers are kept once, in the global blobstore" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`

    local manifest=$(curl -s -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        http://127.0.0.1:${zot_port}/v2/dup-a/manifests/3.17.3)
    local layer=$(echo "${manifest}" | jq -r '.layers[0].digest')
    local layer_size=$(echo "${manifest}" | jq -r '.layers[0].size')
    [ -n "${layer}" ]

    [ "$(object_size _blobstore ${layer})" = "${layer_size}" ]
    [ "$(object_size dup-a ${layer})" = "0" ]
    [ "$(object_size dup-b ${layer})" = "0" ]
}

@test "[new] both images pull back with unchanged digests" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    local digests_file=${BATS_FILE_TMPDIR}/digests.txt
    [ -s "${digests_file}" ]

    while IFS='=' read -r repo expected_digest; do
        run skopeo --insecure-policy copy --src-tls-verify=false \
            docker://127.0.0.1:${zot_port}/${repo}:3.17.3 oci:${BATS_FILE_TMPDIR}/pulled-${repo}:3.17.3
        [ "$status" -eq 0 ]

        local digest=$(skopeo inspect --tls-verify=false docker://127.0.0.1:${zot_port}/${repo}:3.17.3 | jq -r '.Digest')
        [ "${digest}" = "${expected_digest}" ]
    done < "${digests_file}"
}

@test "[new] deleting one repo's image leaves the other pullable" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    local digest=$(skopeo inspect --tls-verify=false docker://127.0.0.1:${zot_port}/dup-a:3.17.3 | jq -r '.Digest')

    run curl -s -o /dev/null -w "%{http_code}" -X DELETE \
        http://127.0.0.1:${zot_port}/v2/dup-a/manifests/${digest}
    [ "$status" -eq 0 ]
    [ "${output}" = "202" ]

    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:${zot_port}/dup-b:3.17.3 oci:${BATS_FILE_TMPDIR}/after-delete:3.17.3
    [ "$status" -eq 0 ]
}
