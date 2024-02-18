# Note: Intended to be run as "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot

function verify_prerequisites() {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v jq) ] &>/dev/null; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function setup() {
    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20

    # Setup zot server
    ZOT_ROOT_DIR=${BATS_FILE_TMPDIR}/zot
    echo ${ZOT_ROOT_DIR}
    ZOT_LOG_FILE=${ZOT_ROOT_DIR}/zot-log.json
    ZOT_CONFIG_FILE=${BATS_FILE_TMPDIR}/zot_config.json
    mkdir -p ${ZOT_ROOT_DIR}
    touch ${ZOT_LOG_FILE}
    zot_port=$(get_free_port)
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    cat >${ZOT_CONFIG_FILE} <<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${ZOT_ROOT_DIR}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}"
    },
    "log": {
        "level": "debug",
        "output": "${ZOT_LOG_FILE}"
    },
    "extensions": {
        "search": {
            "enable": true
        }
    }
}
EOF

    # Add artifact contents to files
    ARTIFACT_BLOBS_DIR=${BATS_FILE_TMPDIR}/artifact-blobs
    mkdir -p ${ARTIFACT_BLOBS_DIR}

    IMAGE_MANIFEST_REFERRER=${ARTIFACT_BLOBS_DIR}/image-manifest-ref-blob
    echo IMAGE_MANIFEST_REFERRER=${IMAGE_MANIFEST_REFERRER}
    touch ${IMAGE_MANIFEST_REFERRER}
    cat >${IMAGE_MANIFEST_REFERRER} <<EOF
        This artifact is represented as an ispec image manifest, this is the layer inside the manifest.
EOF

    zot_serve ${ZOT_PATH} ${ZOT_CONFIG_FILE}
    wait_zot_reachable ${zot_port}

    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]

    run oras attach --plain-http --image-spec v1.1-image --artifact-type image.artifact/type 127.0.0.1:${zot_port}/golang:1.20 ${IMAGE_MANIFEST_REFERRER}
    [ "$status" -eq 0 ]

    MANIFEST_DIGEST=$(skopeo inspect --tls-verify=false docker://localhost:${zot_port}/golang:1.20 | jq -r '.Digest')
    echo ${MANIFEST_DIGEST}

    curl -X GET http://127.0.0.1:${zot_port}/v2/golang/referrers/${MANIFEST_DIGEST}?artifactType=image.artifact/type
}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot/zot-log.json
}

function teardown_file() {
    zot_stop_all
}

@test "add referrers, one artifact and one image" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    # Check referrers API using the normal REST endpoint
    run curl -X GET http://127.0.0.1:${zot_port}/v2/golang/referrers/${MANIFEST_DIGEST}?artifactType=image.artifact/type
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].artifactType') = '"image.artifact/type"' ]

    # Check referrers API using the GQL endpoint
    REFERRER_QUERY_DATA="{ \"query\": \"{ Referrers(repo:\\\"golang\\\", digest:\\\"${MANIFEST_DIGEST}\\\", type:[\\\"image.artifact/type\\\"]) { MediaType ArtifactType Digest Size} }\"}"
    run curl -X POST -H "Content-Type: application/json" --data "${REFERRER_QUERY_DATA}" http://localhost:${zot_port}/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.data.Referrers[].ArtifactType') = '"image.artifact/type"' ]
}
