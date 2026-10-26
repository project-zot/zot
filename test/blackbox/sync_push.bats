# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci".
#       Makefile target installs & checks all necessary tooling.
#       This file needs no image registry from the internet: the image is created through the
#       HTTP API, so the only prerequisite is the zot binary plus curl and jq.

load helpers_zot
load helpers_wait
load ../port_helper

REPO="library/harness"
TAG="1.0"

function verify_prerequisites() {
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

# upload_blob pushes one blob into a registry and returns nothing.
function upload_blob() {
    local addr=$1 repo=$2 digest=$3 body=$4
    local location
    location=$(curl -fsS -X POST "${addr}/v2/${repo}/blobs/uploads/" -o /dev/null -D - |
        awk 'tolower($1)=="location:" {print $2}' | tr -d '\r')
    curl -fsS -X PUT "${addr}${location}?digest=${digest}" --data-binary "${body}" -o /dev/null
}

# put_manifest uploads a manifest by reference and returns its digest.
function put_manifest() {
    local addr=$1 repo=$2 reference=$3 body=$4
    curl -fsS -X PUT "${addr}/v2/${repo}/manifests/${reference}" \
        -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' \
        --data-binary "${body}" -o /dev/null -D - |
        awk 'tolower($1)=="docker-content-digest:" {print $2}' | tr -d '\r'
}

# wait_for_digest waits until addr serves want for repo:reference.
function wait_for_digest() {
    local addr=$1 repo=$2 reference=$3 want=$4
    local got
    for _ in $(seq 1 120); do
        got=$(curl -fsS -I "${addr}/v2/${repo}/manifests/${reference}" \
            -H 'Accept: application/vnd.oci.image.manifest.v1+json' 2>/dev/null |
            awk 'tolower($1)=="docker-content-digest:" {print $2}' | tr -d '\r')
        [ "${got}" = "${want}" ] && return 0
        sleep 0.5
    done
    return 1
}

function setup_file() {
    if ! verify_prerequisites; then
        exit 1
    fi

    export SRC_PORT=$(get_free_port_for_service "zotsrc")
    export DST_PORT=$(get_free_port_for_service "zotdst")
    export SRC_ADDR="http://127.0.0.1:${SRC_PORT}"
    export DST_ADDR="http://127.0.0.1:${DST_PORT}"

    local src_root=${BATS_FILE_TMPDIR}/src
    local dst_root=${BATS_FILE_TMPDIR}/dst
    export SRC_LOG=${BATS_FILE_TMPDIR}/src-log.json
    mkdir -p ${src_root} ${dst_root}

    cat >${BATS_FILE_TMPDIR}/dst.json <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {"rootDirectory": "${dst_root}"},
    "http": {"address": "127.0.0.1", "port": "${DST_PORT}"},
    "log": {"level": "debug", "output": "${BATS_FILE_TMPDIR}/dst-log.json"}
}
EOF

    cat >${BATS_FILE_TMPDIR}/src.json <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {"rootDirectory": "${src_root}"},
    "http": {"address": "127.0.0.1", "port": "${SRC_PORT}"},
    "log": {"level": "debug", "output": "${SRC_LOG}"},
    "extensions": {
        "sync": {
            "enable": true,
            "registries": [
                {
                    "pollInterval": "1s",
                    "content": [{"prefix": "library/**"}],
                    "push": {
                        "enabled": true,
                        "urls": ["http://127.0.0.1:${DST_PORT}"],
                        "tlsVerify": false
                    }
                }
            ]
        }
    }
}
EOF

    ${ZOT_PATH} verify ${BATS_FILE_TMPDIR}/src.json
    ${ZOT_PATH} verify ${BATS_FILE_TMPDIR}/dst.json

    zot_serve ${ZOT_PATH} ${BATS_FILE_TMPDIR}/dst.json
    zot_serve ${ZOT_PATH} ${BATS_FILE_TMPDIR}/src.json
    wait_zot_reachable ${DST_PORT}
    wait_zot_reachable ${SRC_PORT}

    export CONFIG_BODY='{"architecture":"amd64","os":"linux"}'
    export LAYER_BODY='the-layer-bytes'
    export CONFIG_DIGEST="sha256:$(printf '%s' "${CONFIG_BODY}" | sha256sum | cut -d' ' -f1)"
    export LAYER_DIGEST="sha256:$(printf '%s' "${LAYER_BODY}" | sha256sum | cut -d' ' -f1)"

    upload_blob ${SRC_ADDR} ${REPO} ${CONFIG_DIGEST} "${CONFIG_BODY}"
    upload_blob ${SRC_ADDR} ${REPO} ${LAYER_DIGEST} "${LAYER_BODY}"

    local config_size=$(printf '%s' "${CONFIG_BODY}" | wc -c)
    local layer_size=$(printf '%s' "${LAYER_BODY}" | wc -c)

    export IMAGE_MANIFEST=$(cat <<EOF
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "${CONFIG_DIGEST}", "size": ${config_size}},
  "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "${LAYER_DIGEST}", "size": ${layer_size}}]
}
EOF
)
    export IMAGE_DIGEST="sha256:$(printf '%s' "${IMAGE_MANIFEST}" | sha256sum | cut -d' ' -f1)"
    export IMAGE_SIZE=$(printf '%s' "${IMAGE_MANIFEST}" | wc -c)

    put_manifest ${SRC_ADDR} ${REPO} ${TAG} "${IMAGE_MANIFEST}" > /dev/null
}

function teardown_file() {
    zot_stop_all
}

@test "push mirrors a tag and its blobs to the destination" {
    run wait_for_digest ${DST_ADDR} ${REPO} ${TAG} ${IMAGE_DIGEST}
    [ "$status" -eq 0 ]

    # the layer has to be byte-identical on the destination, not only the manifest
    curl -fsS "${DST_ADDR}/v2/${REPO}/blobs/${LAYER_DIGEST}" -o ${BATS_FILE_TMPDIR}/layer.bin
    run cmp -s ${BATS_FILE_TMPDIR}/layer.bin <(printf '%s' "${LAYER_BODY}")
    [ "$status" -eq 0 ]

    run curl -fsS "${DST_ADDR}/v2/_catalog"
    [ "$status" -eq 0 ]
    echo "$output" | jq -e --arg repo "${REPO}" '.repositories | index($repo)'
}

@test "a tag the destination already has is skipped on the next cycle" {
    run wait_for_digest ${DST_ADDR} ${REPO} ${TAG} ${IMAGE_DIGEST}
    [ "$status" -eq 0 ]

    # the loop runs every second, so a second delta check happens quickly
    local found=1
    for _ in $(seq 1 60); do
        if grep -q "destination already has this digest, skipping push" ${SRC_LOG} 2>/dev/null; then
            found=0
            break
        fi
        sleep 0.5
    done
    [ "${found}" -eq 0 ]
}

@test "a referrer that arrives after the image is pushed too" {
    run wait_for_digest ${DST_ADDR} ${REPO} ${TAG} ${IMAGE_DIGEST}
    [ "$status" -eq 0 ]

    local empty_body='{}'
    local empty_digest="sha256:$(printf '%s' "${empty_body}" | sha256sum | cut -d' ' -f1)"
    local sig_body='a-signature'
    local sig_digest="sha256:$(printf '%s' "${sig_body}" | sha256sum | cut -d' ' -f1)"
    upload_blob ${SRC_ADDR} ${REPO} ${empty_digest} "${empty_body}"
    upload_blob ${SRC_ADDR} ${REPO} ${sig_digest} "${sig_body}"

    local sig_manifest=$(cat <<EOF
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.example.signature",
  "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": "${empty_digest}", "size": 2},
  "layers": [{"mediaType": "application/vnd.example.signature", "digest": "${sig_digest}", "size": 11}],
  "subject": {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "${IMAGE_DIGEST}", "size": ${IMAGE_SIZE}}
}
EOF
)
    local sig_manifest_digest="sha256:$(printf '%s' "${sig_manifest}" | sha256sum | cut -d' ' -f1)"
    put_manifest ${SRC_ADDR} ${REPO} ${sig_manifest_digest} "${sig_manifest}" > /dev/null

    local found=1
    for _ in $(seq 1 120); do
        if curl -fsS "${DST_ADDR}/v2/${REPO}/referrers/${IMAGE_DIGEST}" 2>/dev/null |
            jq -e --arg digest "${sig_manifest_digest}" '.manifests[] | select(.digest == $digest)' > /dev/null; then
            found=0
            break
        fi
        sleep 0.5
    done
    [ "${found}" -eq 0 ]
}

@test "a multi-arch index is mirrored with all of its children" {
    local arm64_body='{"architecture":"arm64","os":"linux"}'
    local arm64_digest="sha256:$(printf '%s' "${arm64_body}" | sha256sum | cut -d' ' -f1)"
    local arm64_layer='arm64-layer'
    local arm64_layer_digest="sha256:$(printf '%s' "${arm64_layer}" | sha256sum | cut -d' ' -f1)"
    upload_blob ${SRC_ADDR} ${REPO} ${arm64_digest} "${arm64_body}"
    upload_blob ${SRC_ADDR} ${REPO} ${arm64_layer_digest} "${arm64_layer}"

    local arm64_manifest=$(cat <<EOF
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "${arm64_digest}", "size": ${#arm64_body}},
  "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "${arm64_layer_digest}", "size": ${#arm64_layer}}]
}
EOF
)
    local arm64_manifest_digest="sha256:$(printf '%s' "${arm64_manifest}" | sha256sum | cut -d' ' -f1)"
    put_manifest ${SRC_ADDR} ${REPO} "arm64-child" "${arm64_manifest}" > /dev/null

    local index=$(cat <<EOF
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "${IMAGE_DIGEST}", "size": ${IMAGE_SIZE}, "platform": {"os": "linux", "architecture": "amd64"}},
    {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "${arm64_manifest_digest}", "size": ${#arm64_manifest}, "platform": {"os": "linux", "architecture": "arm64"}}
  ]
}
EOF
)
    local index_digest="sha256:$(printf '%s' "${index}" | sha256sum | cut -d' ' -f1)"
    curl -fsS -X PUT "${SRC_ADDR}/v2/${REPO}/manifests/multiarch" \
        -H 'Content-Type: application/vnd.oci.image.index.v1+json' \
        --data-binary "${index}" -o /dev/null

    run wait_for_digest ${DST_ADDR} ${REPO} multiarch ${index_digest}
    [ "$status" -eq 0 ]

    run curl -fsS "${DST_ADDR}/v2/${REPO}/manifests/${arm64_manifest_digest}" \
        -H 'Accept: application/vnd.oci.image.manifest.v1+json'
    [ "$status" -eq 0 ]
}

@test "a push entry without a content allowlist is rejected at config load" {
    cat >${BATS_FILE_TMPDIR}/bad.json <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {"rootDirectory": "${BATS_FILE_TMPDIR}/bad"},
    "http": {"address": "127.0.0.1", "port": "${SRC_PORT}"},
    "extensions": {
        "sync": {
            "enable": true,
            "registries": [
                {
                    "pollInterval": "1s",
                    "push": {"enabled": true, "urls": ["http://127.0.0.1:${DST_PORT}"]}
                }
            ]
        }
    }
}
EOF

    run ${ZOT_PATH} verify ${BATS_FILE_TMPDIR}/bad.json
    [ "$status" -ne 0 ]
    echo "$output" | grep -q "content is required for a push registry"
}
