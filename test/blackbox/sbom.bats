# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling.

load helpers_zot
load ../port_helper

function verify_prerequisites {
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

    return 0
}

function setup_file() {
    if ! verify_prerequisites; then
        exit 1
    fi

    skopeo --insecure-policy copy --format=oci \
        docker://ghcr.io/project-zot/golang:1.20 \
        oci:${TEST_DATA_DIR}/golang:1.20

    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    mkdir -p ${zot_root_dir}

    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port

    cat >${zot_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}"
    },
    "log": {
        "level": "debug",
        "output": "${BATS_FILE_TMPDIR}/zot.log"
    },
    "extensions": {
        "search": {
            "enable": true,
            "cve": {
                "updateInterval": "24h",
                "trivy": {
                    "sbom": {
                        "enable": true,
                        "format": "spdx-json"
                    }
                }
            }
        }
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}
}

function teardown() {
    cat ${BATS_FILE_TMPDIR}/zot.log
}

function teardown_file() {
    zot_stop_all
}

@test "sbom referrer is created and queryable via REST+GraphQL" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`

    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 0 ]

    run skopeo inspect --tls-verify=false docker://127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 0 ]
    manifest_digest=$(echo "${output}" | jq -r '.Digest')
    [ -n "${manifest_digest}" ]

    cve_query="{ \"query\": \"{ CVEListForImage(image: \\\"golang@${manifest_digest}\\\", requestedPage: {limit: 1, offset: 0}) { Tag Page { TotalCount ItemCount } Summary { Count } } }\" }"
    run curl -sS -X POST -H "Content-Type: application/json" --data "${cve_query}" \
        http://127.0.0.1:${zot_port}/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    [ $(echo "${output}" | jq -r '.data.CVEListForImage.Tag != null') = "true" ]

    sbom_ref_digest=""
    for _ in $(seq 1 40); do
        resp=$(curl -sS "http://127.0.0.1:${zot_port}/v2/golang/referrers/${manifest_digest}?artifactType=application/spdx%2Bjson")
        sbom_ref_digest=$(echo "${resp}" | jq -r '.manifests[0].digest // ""')
        if [ -n "${sbom_ref_digest}" ]; then
            break
        fi
        sleep 1
    done

    [ -n "${sbom_ref_digest}" ]
    [ $(echo "${resp}" | jq -r '.manifests[0].artifactType') = "application/spdx+json" ]

    ref_query="{ \"query\": \"{ Referrers(repo:\\\"golang\\\", digest:\\\"${manifest_digest}\\\", type:[\\\"application/spdx+json\\\"]) { MediaType ArtifactType Digest Size } }\" }"
    run curl -sS -X POST -H "Content-Type: application/json" --data "${ref_query}" \
        http://127.0.0.1:${zot_port}/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    [ $(echo "${output}" | jq -r '.data.Referrers[0].ArtifactType') = "application/spdx+json" ]
    [ $(echo "${output}" | jq -r '.data.Referrers[0].Digest') = "${sbom_ref_digest}" ]

    run curl -sS -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        http://127.0.0.1:${zot_port}/v2/golang/manifests/${sbom_ref_digest}
    [ "$status" -eq 0 ]
    sbom_layer_digest=$(echo "${output}" | jq -r '.layers[0].digest')
    [ -n "${sbom_layer_digest}" ]

    run curl -sS http://127.0.0.1:${zot_port}/v2/golang/blobs/${sbom_layer_digest}
    [ "$status" -eq 0 ]
    [ $(echo "${output}" | jq -r '.spdxVersion') = "SPDX-2.3" ]
    [ $(echo "${output}" | jq -r '.packages | length') -gt 0 ]
}