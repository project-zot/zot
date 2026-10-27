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


# build_multiarch_index uploads two untagged child manifests and an index that references them,
# the way a real multi-arch image looks. Echoes "<index> <amd64> <arm64>".
function build_multiarch_index() {
    local addr=$1 repo=$2 tag=$3
    local child_digests=()
    local arch cfg cfg_digest layer layer_digest child child_digest

    for arch in amd64 arm64; do
        cfg="{\"architecture\":\"${arch}\",\"os\":\"linux\"}"
        cfg_digest="sha256:$(printf '%s' "${cfg}" | sha256sum | cut -d' ' -f1)"
        layer="${arch}-layer"
        layer_digest="sha256:$(printf '%s' "${layer}" | sha256sum | cut -d' ' -f1)"
        upload_blob "${addr}" "${repo}" "${cfg_digest}" "${cfg}"
        upload_blob "${addr}" "${repo}" "${layer_digest}" "${layer}"

        child=$(printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"%s","size":%d},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"%s","size":%d}]}' \
            "${cfg_digest}" "${#cfg}" "${layer_digest}" "${#layer}")
        child_digest="sha256:$(printf '%s' "${child}" | sha256sum | cut -d' ' -f1)"

        # digest-addressed, so the child has no tag of its own: only the index reaches it
        put_manifest "${addr}" "${repo}" "${child_digest}" "${child}" > /dev/null
        child_digests+=("${child_digest}")
    done

    local amd64_gz arm64_gz
    amd64_gz=$(printf '%s' "amd64-layer" | wc -c)
    arm64_gz=$(printf '%s' "arm64-layer" | wc -c)

    local index
    index=$(printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":1,"platform":{"os":"linux","architecture":"amd64"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":1,"platform":{"os":"linux","architecture":"arm64"}}]}' \
        "${child_digests[0]}" "${child_digests[1]}")

    curl -fsS -X PUT "${addr}/v2/${repo}/manifests/${tag}" \
        -H 'Content-Type: application/vnd.oci.image.index.v1+json' \
        --data-binary "${index}" -o /dev/null

    echo "sha256:$(printf '%s' "${index}" | sha256sum | cut -d' ' -f1) ${child_digests[0]} ${child_digests[1]}"
}

function setup_file() {
    if ! verify_prerequisites; then
        exit 1
    fi

    export SRC_PORT=$(get_free_port_for_service "zotsrc")
    export DST_PORT=$(get_free_port_for_service "zotdst")
    export FILTERED_PORT=$(get_free_port_for_service "zotfiltered")
    export SRC_ADDR="http://127.0.0.1:${SRC_PORT}"
    export DST_ADDR="http://127.0.0.1:${DST_PORT}"
    export FILTERED_ADDR="http://127.0.0.1:${FILTERED_PORT}"

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

    cat >${BATS_FILE_TMPDIR}/filtered.json <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {"rootDirectory": "${BATS_FILE_TMPDIR}/filtered"},
    "http": {"address": "127.0.0.1", "port": "${FILTERED_PORT}"},
    "log": {"level": "debug", "output": "${BATS_FILE_TMPDIR}/filtered-log.json"},
    "extensions": {
        "sync": {
            "enable": true,
            "registries": [
                {
                    "pollInterval": "1s",
                    "content": [{"prefix": "library/filtered"}],
                    "push": {
                        "enabled": true,
                        "urls": ["http://127.0.0.1:${DST_PORT}"],
                        "tlsVerify": false,
                        "platforms": ["linux/amd64"]
                    }
                }
            ]
        }
    }
}
EOF

    mkdir -p ${BATS_FILE_TMPDIR}/filtered

    ${ZOT_PATH} verify ${BATS_FILE_TMPDIR}/src.json
    ${ZOT_PATH} verify ${BATS_FILE_TMPDIR}/dst.json
    ${ZOT_PATH} verify ${BATS_FILE_TMPDIR}/filtered.json

    zot_serve ${ZOT_PATH} ${BATS_FILE_TMPDIR}/dst.json
    zot_serve ${ZOT_PATH} ${BATS_FILE_TMPDIR}/src.json
    zot_serve ${ZOT_PATH} ${BATS_FILE_TMPDIR}/filtered.json
    wait_zot_reachable ${DST_PORT}
    wait_zot_reachable ${SRC_PORT}
    wait_zot_reachable ${FILTERED_PORT}

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
    local repo="library/multi"

    read -r index_digest amd64_digest arm64_digest < <(build_multiarch_index "${SRC_ADDR}" "${repo}" "1.0")
    [ -n "${arm64_digest}" ]

    run wait_for_digest ${DST_ADDR} ${repo} "1.0" "${index_digest}"
    [ "$status" -eq 0 ]

    local digest
    for digest in "${amd64_digest}" "${arm64_digest}"; do
        run curl -fsS -o /dev/null "${DST_ADDR}/v2/${repo}/manifests/${digest}"
        [ "$status" -eq 0 ]
    done
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

@test "a filtered mirror serves the selected platform and keeps the index digest" {
    local repo="library/filtered"

    read -r index_digest amd64_digest arm64_digest < <(build_multiarch_index "${FILTERED_ADDR}" "${repo}" "1.0")
    [ -n "${arm64_digest}" ]

    run wait_for_digest ${DST_ADDR} ${repo} "1.0" "${index_digest}"
    [ "$status" -eq 0 ]

    # the index is unchanged, so its digest and any signature over it survive
    run curl -fsS -o /dev/null "${DST_ADDR}/v2/${repo}/blobs/${amd64_digest}"
    [ "$status" -eq 0 ]

    # the unselected platform is listed by the index but has no manifest here
    run curl -fsS -o /dev/null "${DST_ADDR}/v2/${repo}/manifests/${arm64_digest}"
    [ "$status" -ne 0 ]
}
