# Note: Intended to be run as "make run-blackbox-cloud-ci" or
#       "make run-blackbox-tests BATS_TEST_FILE_PATH=test/blackbox/s3_fresh_root_recovery.bats"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()
#
# Recovery of a migrated remote-storage registry from an empty local root.
#
# The global blobstore migration promotes every repository blob into the shared _blobstore
# object and deletes the repository's own copy, recording "repo X owns digest D" only in the
# local blob-ref cache under rootDirectory. The bucket alone therefore no longer says which
# repository owns what, and the migration marker in the bucket keeps the migration from ever
# running again. A deployment that loses or replaces its local root - a redeployed container
# with a fresh volume, a rebuilt node, a second instance pointed at an existing bucket - then
# starts against a fully intact bucket with no ownership records at all.
#
# Two things have to hold in that state, and this suite asserts both:
#   * reads still resolve: tag listing, manifest by tag, and direct blob HEAD/GET;
#   * garbage collection leaves index.json alone. GC enumerates repo blobs through the same
#     blob-ref index, so an empty index used to read as "every manifest is stale", which
#     rewrote index.json to an empty manifest list and destroyed the tag graph for good.
#
# The gc assertion runs before any read, because a successful read restores the blob ref it
# resolved and would otherwise repopulate the index before gc ever looks at it.

load helpers_zot
load ../port_helper

ZOT_S3_BUCKET="zot-fresh-root-recovery"
ZOT_S3_ROOT="/zot"
ZOT_S3_REGION="us-east-2"
IMAGE_REPO="alpine"
IMAGE_TAG="3.17.3"

function verify_prerequisites() {
    local tool

    for tool in curl jq skopeo awslocal sha256sum; do
        if ! command -v "${tool}" >/dev/null; then
            echo "you need to install ${tool} as a prerequisite to running the tests" >&3
            return 1
        fi
    done

    return 0
}

function get_zot_port() {
    cat "${BATS_FILE_TMPDIR}/zot.port"
}

# Writes an s3-backed zot config. remoteCache is deliberately false: the blob-ref index has to
# live in the local root for this suite to be about losing it. With a remote cache the refs
# outlive the root and there is nothing to recover from.
function write_s3_config() {
    local config_file=${1}
    local root_dir=${2}
    local log_file=${3}
    local gc=${4}
    local zot_port=$(get_zot_port)

    cat > ${config_file}<<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${root_dir}",
        "dedupe": true,
        "remoteCache": false,
        "gc": ${gc},
        "gcDelay": "1s",
        "gcInterval": "2s",
        "storageDriver": {
            "name": "s3",
            "rootdirectory": "${ZOT_S3_ROOT}",
            "region": "${ZOT_S3_REGION}",
            "regionendpoint": "localhost:4566",
            "bucket": "${ZOT_S3_BUCKET}",
            "secure": false,
            "skipverify": false
        }
    },
    "http": {
        "address": "127.0.0.1",
        "port": "${zot_port}"
    },
    "log": {
        "level": "debug",
        "output": "${log_file}"
    }
}
EOF
}

# Lists every object key the registry holds in the bucket.
function s3_keys() {
    awslocal s3 ls --recursive s3://${ZOT_S3_BUCKET} | awk '{print $4}'
}

# Copies the repository's authoritative index.json out of the bucket. The key is looked up
# rather than composed, so the test does not encode how the driver lays the storage root out.
function fetch_repo_index() {
    local dest=${1}
    local key=$(s3_keys | grep -E "/${IMAGE_REPO}/index\.json$" | head -n1)

    if [ -z "${key}" ]; then
        echo "no index.json found in s3://${ZOT_S3_BUCKET} for repository ${IMAGE_REPO}" >&3
        return 1
    fi

    awslocal s3 cp s3://${ZOT_S3_BUCKET}/${key} ${dest}
}

function setup_file() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi

    # localstack accepts any credentials, but the AWS SDK still requires a pair to be present,
    # for zot and for awslocal alike. CI exports its own; default them so a local run works too.
    export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-fake}"
    export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-fake}"
    export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-${ZOT_S3_REGION}}"

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci \
        docker://ghcr.io/project-zot/test-images/${IMAGE_REPO}:${IMAGE_TAG} \
        oci:${TEST_DATA_DIR}/${IMAGE_REPO}:${IMAGE_TAG}

    local zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port

    # The migrated root is the one that lives through the upgrade; the fresh root is the empty
    # one the recovery is exercised from.
    mkdir -p ${BATS_FILE_TMPDIR}/migrated-root
    mkdir -p ${BATS_FILE_TMPDIR}/fresh-root

    # gc is off for the release and migration phases so nothing prunes while the layout is
    # being set up; the fresh-root phase is the one that has to survive it.
    write_s3_config ${BATS_FILE_TMPDIR}/zot_config_release.json \
        ${BATS_FILE_TMPDIR}/migrated-root ${BATS_FILE_TMPDIR}/zot-log-release.json false
    write_s3_config ${BATS_FILE_TMPDIR}/zot_config_migrate.json \
        ${BATS_FILE_TMPDIR}/migrated-root ${BATS_FILE_TMPDIR}/zot-log-migrate.json false
    write_s3_config ${BATS_FILE_TMPDIR}/zot_config_fresh.json \
        ${BATS_FILE_TMPDIR}/fresh-root ${BATS_FILE_TMPDIR}/zot-log-fresh.json true

    awslocal s3 --region ${ZOT_S3_REGION} mb s3://${ZOT_S3_BUCKET}

    zot_rel_serve ${BATS_FILE_TMPDIR}/zot_config_release.json
    wait_zot_reachable ${zot_port}
}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot-log-release.json 2>/dev/null || true
    cat ${BATS_FILE_TMPDIR}/zot-log-migrate.json 2>/dev/null || true
    cat ${BATS_FILE_TMPDIR}/zot-log-fresh.json 2>/dev/null || true
}

function teardown_file() {
    zot_stop_all
    awslocal s3 rb s3://${ZOT_S3_BUCKET} --force || true
}

# ==============================================================================
# RELEASE - populate the bucket in the pre-migration, per-repo blob layout
# ==============================================================================

@test "[release] push image to remote storage" {
    local zot_port=$(get_zot_port)

    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/${IMAGE_REPO}:${IMAGE_TAG} \
        docker://127.0.0.1:${zot_port}/${IMAGE_REPO}:${IMAGE_TAG}
    [ "$status" -eq 0 ]

    run curl -f -s http://127.0.0.1:${zot_port}/v2/${IMAGE_REPO}/tags/list
    [ "$status" -eq 0 ]
    echo "${output}" | jq -e --arg tag "${IMAGE_TAG}" '.tags | index($tag) != null'
}

@test "[release] record the image digests to resolve after recovery" {
    local zot_port=$(get_zot_port)
    local digests_file=${BATS_FILE_TMPDIR}/blob-digests.txt
    local manifest_file=${BATS_FILE_TMPDIR}/manifest.json

    run skopeo inspect --tls-verify=false --raw \
        docker://127.0.0.1:${zot_port}/${IMAGE_REPO}:${IMAGE_TAG}
    [ "$status" -eq 0 ]
    echo "${output}" > ${manifest_file}

    # The manifest's own digest is what the tag has to keep resolving to.
    skopeo inspect --tls-verify=false docker://127.0.0.1:${zot_port}/${IMAGE_REPO}:${IMAGE_TAG} \
        | jq -r '.Digest' > ${BATS_FILE_TMPDIR}/manifest-digest.txt
    [ -s ${BATS_FILE_TMPDIR}/manifest-digest.txt ]

    # Config and layers are the payloads the migration moves into the shared blobstore, so
    # they are what the direct blob reads below have to find there.
    jq -r '.config.digest, .layers[].digest' ${manifest_file} > ${digests_file}
    [ -s ${digests_file} ]
}

# ==============================================================================
# MIGRATE - upgrade in place to the global blobstore layout
# ==============================================================================

@test "[migrate] upgrade to the new binary and migrate to the global blobstore" {
    local zot_port=$(get_zot_port)

    zot_stop_all
    zot_serve ${ZOT_PATH} ${BATS_FILE_TMPDIR}/zot_config_migrate.json
    wait_zot_reachable ${zot_port}

    run grep -q "global blobstore upgrade completed" ${BATS_FILE_TMPDIR}/zot-log-migrate.json
    [ "$status" -eq 0 ]
}

@test "[migrate] the bucket keeps blobs only in the global blobstore" {
    # This is the precondition the whole suite rests on: after the migration the repo's payloads
    # exist only under _blobstore, so nothing in the bucket records which repo owns them. If this
    # ever stops holding, the recovery tests below would pass for the wrong reason.
    run s3_keys
    [ "$status" -eq 0 ]

    echo "${output}" | grep -q "_blobstore/blobs/sha256/"
    ! echo "${output}" | grep -q "${IMAGE_REPO}/blobs/sha256/"
}

@test "[migrate] record the repository index.json baseline" {
    fetch_repo_index ${BATS_FILE_TMPDIR}/index-baseline.json
    [ -s ${BATS_FILE_TMPDIR}/index-baseline.json ]

    # A baseline that is already empty would make the comparison below vacuous.
    run jq -r '.manifests | length' ${BATS_FILE_TMPDIR}/index-baseline.json
    [ "$status" -eq 0 ]
    [ "${output}" -gt 0 ]
}

# ==============================================================================
# FRESH ROOT - same bucket, empty local root, no ownership records at all
# ==============================================================================

@test "[fresh root] start against the same bucket with an empty local root" {
    local zot_port=$(get_zot_port)

    zot_stop_all

    # Discard the local root entirely: the blob-ref index, the boltdb cache and the metadata
    # all go with it. The bucket is untouched.
    rm -rf ${BATS_FILE_TMPDIR}/fresh-root
    mkdir -p ${BATS_FILE_TMPDIR}/fresh-root
    [ -z "$(ls -A ${BATS_FILE_TMPDIR}/fresh-root)" ]

    zot_serve ${ZOT_PATH} ${BATS_FILE_TMPDIR}/zot_config_fresh.json
    wait_zot_reachable ${zot_port}

    # The migration must not run a second time - the marker in the bucket is what makes this a
    # recovery rather than a re-migration.
    ! grep -q "global blobstore upgrade completed" ${BATS_FILE_TMPDIR}/zot-log-fresh.json

    run curl -f -s http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    echo "${output}" | jq -e --arg repo "${IMAGE_REPO}" '.repositories | index($repo) != null'
}

@test "[fresh root] index.json survives the garbage collection window" {
    # Runs before any read: a successful read restores the blob ref it resolved, which would
    # repopulate the index gc consults and hide a regression here.
    # gcDelay is 1s and gcInterval 2s, so this is many gc passes, not one.
    sleep 30

    fetch_repo_index ${BATS_FILE_TMPDIR}/index-after-gc.json
    [ -s ${BATS_FILE_TMPDIR}/index-after-gc.json ]

    run diff <(jq -S . ${BATS_FILE_TMPDIR}/index-baseline.json) \
             <(jq -S . ${BATS_FILE_TMPDIR}/index-after-gc.json)
    [ "$status" -eq 0 ]
}

@test "[fresh root] tag resolution" {
    local zot_port=$(get_zot_port)

    run curl -f -s http://127.0.0.1:${zot_port}/v2/${IMAGE_REPO}/tags/list
    [ "$status" -eq 0 ]
    echo "${output}" | jq -e --arg tag "${IMAGE_TAG}" '.tags | index($tag) != null'
}

@test "[fresh root] manifest by tag resolves to the same digest" {
    local zot_port=$(get_zot_port)
    local expected_digest=$(cat ${BATS_FILE_TMPDIR}/manifest-digest.txt)

    run curl -f -s -o ${BATS_FILE_TMPDIR}/manifest-after.json \
        -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        http://127.0.0.1:${zot_port}/v2/${IMAGE_REPO}/manifests/${IMAGE_TAG}
    [ "$status" -eq 0 ]

    run sha256sum ${BATS_FILE_TMPDIR}/manifest-after.json
    [ "$status" -eq 0 ]
    [ "sha256:$(echo ${output} | awk '{print $1}')" = "${expected_digest}" ]
}

@test "[fresh root] direct blob HEAD" {
    local zot_port=$(get_zot_port)
    local digests_file=${BATS_FILE_TMPDIR}/blob-digests.txt

    # Fail loudly on a missing/empty file instead of the while loop silently no-op'ing.
    [ -s "${digests_file}" ]

    local checked=0
    local expected_count=$(wc -l < "${digests_file}")

    while read -r digest; do
        run curl -f -s -o /dev/null -w '%{http_code}' -I \
            http://127.0.0.1:${zot_port}/v2/${IMAGE_REPO}/blobs/${digest}
        [ "$status" -eq 0 ]
        [ "${output}" = "200" ]
        checked=$((checked + 1))
    done < "${digests_file}"

    [ "${checked}" -eq "${expected_count}" ]
}

@test "[fresh root] direct blob GET returns the payload" {
    local zot_port=$(get_zot_port)
    local digests_file=${BATS_FILE_TMPDIR}/blob-digests.txt

    [ -s "${digests_file}" ]

    local checked=0
    local expected_count=$(wc -l < "${digests_file}")

    while read -r digest; do
        run curl -f -s -o ${BATS_FILE_TMPDIR}/blob.bin \
            http://127.0.0.1:${zot_port}/v2/${IMAGE_REPO}/blobs/${digest}
        [ "$status" -eq 0 ]

        # A 200 with the wrong bytes would be a worse failure than a 404, so verify the content.
        run sha256sum ${BATS_FILE_TMPDIR}/blob.bin
        [ "$status" -eq 0 ]
        [ "sha256:$(echo ${output} | awk '{print $1}')" = "${digest}" ]
        checked=$((checked + 1))
    done < "${digests_file}"

    [ "${checked}" -eq "${expected_count}" ]
}

@test "[fresh root] pull the image end to end" {
    local zot_port=$(get_zot_port)

    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:${zot_port}/${IMAGE_REPO}:${IMAGE_TAG} \
        oci:${TEST_DATA_DIR}/${IMAGE_REPO}-recovered:${IMAGE_TAG}
    [ "$status" -eq 0 ]
}

@test "[fresh root] the resolved blob references are written back" {
    # The recovery is meant to heal the root as it reads, not to re-walk the manifest graph on
    # every request, so the reads above must have left ownership records behind.
    run grep -q "restored blob reference from the global blobstore" \
        ${BATS_FILE_TMPDIR}/zot-log-fresh.json
    [ "$status" -eq 0 ]
}
