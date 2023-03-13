load helpers_referrers

function setup() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
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
    cat >${ZOT_CONFIG_FILE} <<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${ZOT_ROOT_DIR}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8080"
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

    ARTIFACT_MANIFEST_REFERRER=${ARTIFACT_BLOBS_DIR}/artifact-manifest-ref-blob
    touch ${ARTIFACT_MANIFEST_REFERRER}
    cat >${ARTIFACT_MANIFEST_REFERRER} <<EOF
        This artifact is represented as an ispec artifact manifest, this is the blob inside the manifest.
EOF

    setup_zot_file_level ${ZOT_CONFIG_FILE}
    echo "yes"
    wait_zot_reachable "http://127.0.0.1:8080/v2/_catalog"

    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:8080/golang:1.20
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:8080/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]

    run oras attach --plain-http --image-spec v1.1-image --artifact-type image.type 127.0.0.1:8080/golang:1.20 ${IMAGE_MANIFEST_REFERRER}
    [ "$status" -eq 0 ]

    run oras attach --plain-http --image-spec v1.1-artifact --artifact-type artifact.type 127.0.0.1:8080/golang:1.20 ${ARTIFACT_MANIFEST_REFERRER}
    [ "$status" -eq 0 ]

    MANIFEST_DIGEST=$(skopeo inspect --tls-verify=false docker://localhost:8080/golang:1.20 | jq -r '.Digest')
    echo ${MANIFEST_DIGEST}

    curl -X GET http://127.0.0.1:8080/v2/golang/referrers/${MANIFEST_DIGEST}?artifactType=image.type
}

function teardown() {
    local ZOT_ROOT_DIR=${BATS_FILE_TMPDIR}/zot
    zot_stop ${BATS_FILE_TMPDIR}
    rm -rf ${ZOT_ROOT_DIR}
}

@test "add referrers, one artifact and one image" {

    # Check referrers API using the normal REST endpoint
    run curl -X GET http://127.0.0.1:8080/v2/golang/referrers/${MANIFEST_DIGEST}?artifactType=image.type
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].artifactType') = '"image.type"' ]

    run curl -X GET http://127.0.0.1:8080/v2/golang/referrers/${MANIFEST_DIGEST}?artifactType=artifact.type
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].artifactType') = '"artifact.type"' ]

    # Check referrers API using the GQL endpoint
    REFERRER_QUERY_DATA="{ \"query\": \"{ Referrers(repo:\\\"golang\\\", digest:\\\"${MANIFEST_DIGEST}\\\", type:[\\\"image.type\\\"]) { MediaType ArtifactType Digest Size} }\"}"
    run curl -X POST -H "Content-Type: application/json" --data "${REFERRER_QUERY_DATA}" http://localhost:8080/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.data.Referrers[].ArtifactType') = '"image.type"' ]

    REFERRER_QUERY_DATA="{ \"query\": \"{ Referrers(repo:\\\"golang\\\", digest:\\\"${MANIFEST_DIGEST}\\\", type:[\\\"artifact.type\\\"]) { MediaType ArtifactType Digest Size} }\"}"
    run curl -X POST -H "Content-Type: application/json" --data "${REFERRER_QUERY_DATA}" http://localhost:8080/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.data.Referrers[].ArtifactType') = '"artifact.type"' ]
}
