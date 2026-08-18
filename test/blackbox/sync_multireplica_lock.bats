# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()
#
# Exercises the distributed on-demand sync lock added in this branch.
# Spins up:
#   - 1 Redis (shared cache backend, source of cluster-wide locks)
#   - 1 upstream zot holding the source image
#   - 2 replica zots, both syncing on-demand from upstream, both pointing
#     at the same Redis cache; local storage is per-replica so the lock
#     itself is the only coordination point.
# Concurrent manifest GETs against the two replicas must produce exactly
# one 200 (the lock holder ran the sync) and one 503 (the loser observed
# the lock and short-circuited).

load helpers_zot
load helpers_redis
load ../port_helper

function verify_prerequisites() {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v docker) ]; then
        echo "you need to install docker as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v skopeo) ]; then
        echo "you need to install skopeo as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function setup_file() {
    if ! $(verify_prerequisites); then
        exit 1
    fi

    skopeo --insecure-policy copy --format=oci \
        docker://ghcr.io/project-zot/test-images/alpine:3.17.3 \
        oci:${TEST_DATA_DIR}/alpine:1

    redis_port=$(get_free_port_for_service "redis")
    redis_start zot_sync_lock_redis ${redis_port}
    echo ${redis_port} > ${BATS_FILE_TMPDIR}/redis.port

    # Give Redis a moment to accept connections.
    sleep 2

    local upstream_root=${BATS_FILE_TMPDIR}/upstream
    local upstream_config=${BATS_FILE_TMPDIR}/upstream.json
    mkdir -p ${upstream_root}

    upstream_port=$(get_free_port_for_service "upstream")
    echo ${upstream_port} > ${BATS_FILE_TMPDIR}/upstream.port

    cat >${upstream_config} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${upstream_root}"
    },
    "http": {
        "address": "127.0.0.1",
        "port": "${upstream_port}"
    },
    "log": {
        "level": "info"
    }
}
EOF
    zot_serve ${ZOT_PATH} ${upstream_config}
    wait_zot_reachable ${upstream_port}

    skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/alpine:1 \
        docker://127.0.0.1:${upstream_port}/alpine:1

    for i in 1 2; do
        local replica_root=${BATS_FILE_TMPDIR}/replica${i}
        local replica_config=${BATS_FILE_TMPDIR}/replica${i}.json
        local replica_log=${BATS_FILE_TMPDIR}/replica${i}.log
        mkdir -p ${replica_root}

        local replica_port=$(get_free_port_for_service "replica${i}")
        echo ${replica_port} > ${BATS_FILE_TMPDIR}/replica${i}.port

        cat >${replica_config} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${replica_root}",
        "cacheDriver": {
            "name": "redis",
            "url": "redis://localhost:${redis_port}",
            "keyprefix": "zot"
        }
    },
    "http": {
        "address": "127.0.0.1",
        "port": "${replica_port}"
    },
    "log": {
        "level": "debug",
        "output": "${replica_log}"
    },
    "extensions": {
        "sync": {
            "enable": true,
            "registries": [
                {
                    "urls": ["http://127.0.0.1:${upstream_port}"],
                    "onDemand": true,
                    "tlsVerify": false,
                    "maxRetries": 0,
                    "content": [{ "prefix": "**" }]
                }
            ]
        }
    }
}
EOF
        zot_serve ${ZOT_PATH} ${replica_config}
        wait_zot_reachable ${replica_port}
    done
}

function teardown_file() {
    zot_stop_all
    redis_stop zot_sync_lock_redis
}

@test "single replica on-demand sync works (sanity)" {
    local replica1_port=$(cat ${BATS_FILE_TMPDIR}/replica1.port)

    run curl -s -o /dev/null -w "%{http_code}" \
        -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        http://127.0.0.1:${replica1_port}/v2/alpine/manifests/1
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" = "200" ]
}

@test "concurrent on-demand sync against two replicas: exactly one 200, one 503" {
    local replica1_port=$(cat ${BATS_FILE_TMPDIR}/replica1.port)
    local replica2_port=$(cat ${BATS_FILE_TMPDIR}/replica2.port)

    # Use a fresh tag so neither replica has it cached locally from prior tests.
    local upstream_port=$(cat ${BATS_FILE_TMPDIR}/upstream.port)
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/alpine:1 \
        docker://127.0.0.1:${upstream_port}/alpine-concurrent:1
    [ "$status" -eq 0 ]

    local out1=$(mktemp)
    local out2=$(mktemp)

    curl -s -o /dev/null -w "%{http_code}" \
        -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        http://127.0.0.1:${replica1_port}/v2/alpine-concurrent/manifests/1 > ${out1} &
    local pid1=$!

    curl -s -o /dev/null -w "%{http_code}" \
        -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        http://127.0.0.1:${replica2_port}/v2/alpine-concurrent/manifests/1 > ${out2} &
    local pid2=$!

    wait $pid1
    wait $pid2

    local code1=$(cat ${out1})
    local code2=$(cat ${out2})
    rm -f ${out1} ${out2}

    echo "replica1=${code1} replica2=${code2}" >&3

    # One replica acquires the distributed lock and serves 200; the other
    # observes the lock and returns 503 + Retry-After.
    [ "${code1}" = "200" ] || [ "${code1}" = "503" ]
    [ "${code2}" = "200" ] || [ "${code2}" = "503" ]
    [ "${code1}" != "${code2}" ]

    # Loser's log must contain the in-flight observation; this is the
    # direct signal that the Redis lock — not just local dedup — fired.
    grep -q "distributed on-demand sync already in flight" \
        ${BATS_FILE_TMPDIR}/replica1.log ${BATS_FILE_TMPDIR}/replica2.log
}
