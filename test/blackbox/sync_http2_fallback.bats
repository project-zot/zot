# Smoke test for the HTTP/2 → HTTP/1.1 fallback transport used by sync.
# The fallback only kicks in when the upstream emits malformed HTTP/2 framing
# (Docker Hub's LB does this occasionally); a normal zot upstream speaks HTTP/2
# cleanly and the primary path is exercised. This test verifies the new
# transport does not break the happy path. Fallback-specific behavior is unit
# tested in pkg/extensions/sync/http2_fallback_test.go.

load helpers_zot
load helpers_wait
load ../port_helper

function verify_prerequisites() {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
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

    local zot_upstream_root_dir=${BATS_FILE_TMPDIR}/zot-upstream
    local zot_downstream_root_dir=${BATS_FILE_TMPDIR}/zot-downstream

    local zot_upstream_config_file=${BATS_FILE_TMPDIR}/zot_upstream_config.json
    local zot_downstream_config_file=${BATS_FILE_TMPDIR}/zot_downstream_config.json

    mkdir -p ${zot_upstream_root_dir}
    mkdir -p ${zot_downstream_root_dir}

    zot_upstream_port=$(get_free_port_for_service "zot_upstream")
    echo ${zot_upstream_port} > ${BATS_FILE_TMPDIR}/zot.upstream.port
    zot_downstream_port=$(get_free_port_for_service "zot_downstream")
    echo ${zot_downstream_port} > ${BATS_FILE_TMPDIR}/zot.downstream.port

    cat >${zot_upstream_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_upstream_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_upstream_port}"
    },
    "log": {
        "level": "debug"
    }
}
EOF

    cat >${zot_downstream_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_downstream_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_downstream_port}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_upstream_port}"
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

    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20

    zot_serve ${ZOT_PATH} ${zot_upstream_config_file}
    wait_zot_reachable ${zot_upstream_port}

    zot_serve ${ZOT_PATH} ${zot_downstream_config_file}
    wait_zot_reachable ${zot_downstream_port}
}

function teardown_file() {
    zot_stop_all
}

@test "sync on-demand happy path with http2 fallback transport" {
    zot_upstream_port=`cat ${BATS_FILE_TMPDIR}/zot.upstream.port`
    zot_downstream_port=`cat ${BATS_FILE_TMPDIR}/zot.downstream.port`

    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_upstream_port}/golang:1.20
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:${zot_upstream_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]

    run curl http://127.0.0.1:${zot_downstream_port}/v2/golang/manifests/1.20
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:${zot_downstream_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]
}
