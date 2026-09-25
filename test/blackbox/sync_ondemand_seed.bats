# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()
#
# Regression coverage for on-demand sync blob seeding (project-zot/zot#4386):
# when an on-demand sync pulls a new tag whose layers the destination repo
# already holds locally, those layers must be seeded from the local store
# instead of being re-downloaded from upstream. We push one image to the
# upstream under two tags, pull the first through the downstream (a full sync),
# then pull the second and assert the upstream served *no* additional blob
# bodies: everything the second tag needs was already local and gets seeded.
# Without seeding, the second pull re-fetches every layer and this fails.

load helpers_zot
load ../port_helper

# Repo on the upstream, and the two tags pointing at the same image. Sharing all
# layers is the strongest form of the overlap the seeder optimizes.
SEED_REPO="seed-test"
SEED_IMAGE="ghcr.io/project-zot/golang:1.20"

function verify_prerequisites() {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v skopeo) ]; then
        echo "you need to install skopeo as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v jq) ]; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

# Counts, in the upstream access log, successful full blob GETs (status 200),
# i.e. how many blob bodies the upstream has served so far.
function upstream_blob_gets() {
    local upstream_log=${BATS_FILE_TMPDIR}/zot-upstream.log

    jq -Rn '[
        inputs
        | fromjson?
        | select(.method == "GET" and .statusCode == 200 and (.path | contains("/blobs/sha256:")))
    ] | length' "${upstream_log}"
}

function setup_file() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi

    local upstream_root_dir=${BATS_FILE_TMPDIR}/zot-upstream
    local downstream_root_dir=${BATS_FILE_TMPDIR}/zot-downstream
    local upstream_config_file=${BATS_FILE_TMPDIR}/zot_upstream_config.json
    local downstream_config_file=${BATS_FILE_TMPDIR}/zot_downstream_config.json

    mkdir -p ${upstream_root_dir}
    mkdir -p ${downstream_root_dir}

    local upstream_port=$(get_free_port_for_service "upstream")
    echo ${upstream_port} >${BATS_FILE_TMPDIR}/zot.upstream_port
    local downstream_port=$(get_free_port_for_service "downstream")
    echo ${downstream_port} >${BATS_FILE_TMPDIR}/zot.downstream_port

    # Plain upstream registry: no sync, just serves what we push to it. Its
    # access log is the measurement surface, so keep it on its own path outside
    # storage so sync/GC can never remove it.
    cat >${upstream_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${upstream_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${upstream_port}"
    },
    "log": {
        "level": "info",
        "output": "${BATS_FILE_TMPDIR}/zot-upstream.log"
    }
}
EOF

    # Downstream registry: on-demand sync of everything from the upstream. This
    # is the build under test; its seeding of already-local layers is what keeps
    # a second, overlapping tag from being re-fetched upstream.
    cat >${downstream_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${downstream_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${downstream_port}"
    },
    "log": {
        "level": "info",
        "output": "${BATS_FILE_TMPDIR}/zot-downstream.log"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${upstream_port}"
                    ],
                    "onDemand": true,
                    "tlsVerify": false,
                    "content": [
                        {
                            "prefix": "**"
                        }
                    ]
                }
            ]
        }
    }
}
EOF

    zot_serve ${ZOT_PATH} ${upstream_config_file}
    wait_zot_reachable ${upstream_port}
    zot_serve ${ZOT_PATH} ${downstream_config_file}
    wait_zot_reachable ${downstream_port}

    # Push one image to the upstream under two tags. The second push only adds a
    # tag (its blobs already exist), so v1 and v2 share every layer.
    skopeo --insecure-policy copy --format=oci docker://${SEED_IMAGE} \
        oci:${TEST_DATA_DIR}/seed:image
    skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/seed:image \
        docker://127.0.0.1:${upstream_port}/${SEED_REPO}:v1
    skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/seed:image \
        docker://127.0.0.1:${upstream_port}/${SEED_REPO}:v2

    run regctl registry set "127.0.0.1:${downstream_port}" --tls disabled
    [ "$status" -eq 0 ]
}

# Print zot logs only when a test fails.
function teardown() {
    dump_zot_logs_on_failure \
        "${BATS_FILE_TMPDIR}/zot-upstream.log" \
        "${BATS_FILE_TMPDIR}/zot-downstream.log"
}

function teardown_file() {
    zot_stop_all
}

@test "on-demand sync of the first tag fetches its layers from upstream" {
    local downstream_port=$(cat ${BATS_FILE_TMPDIR}/zot.downstream_port)

    # Pulling v1 through the downstream triggers an on-demand sync that copies
    # the whole image from the upstream into the downstream store, forcing every
    # layer across the wire.
    run regctl image copy "127.0.0.1:${downstream_port}/${SEED_REPO}:v1" \
        "ocidir://${BATS_FILE_TMPDIR}/pull-v1"
    [ "$status" -eq 0 ]

    # The upstream served at least one blob body for this first sync; record the
    # running total for the next test to compare against.
    local served=$(upstream_blob_gets)
    [ "${served}" -ge 1 ]
    echo "${served}" >${BATS_FILE_TMPDIR}/upstream_blob_gets.after_v1
}

@test "on-demand sync of a second, overlapping tag seeds every layer locally" {
    local downstream_port=$(cat ${BATS_FILE_TMPDIR}/zot.downstream_port)
    local before=$(cat ${BATS_FILE_TMPDIR}/upstream_blob_gets.after_v1)

    # v2 is the same image under a new tag: the downstream already holds all of
    # its layers in ${SEED_REPO}, so seeding satisfies the copy entirely from
    # local storage and the upstream should serve no further blob bodies.
    run regctl image copy "127.0.0.1:${downstream_port}/${SEED_REPO}:v2" \
        "ocidir://${BATS_FILE_TMPDIR}/pull-v2"
    [ "$status" -eq 0 ]

    # No new blob bodies crossed the wire from upstream. Without seeding this
    # count would grow by the full layer set of the image.
    local after=$(upstream_blob_gets)
    [ "${after}" -eq "${before}" ]
}
