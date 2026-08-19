# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_wait
load ../port_helper

function verify_prerequisites() {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v jq) ]; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v cosign) ]; then
        echo "you need to install cosign as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function setup_file() {
    export COSIGN_PASSWORD=""

    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20
    # A second, distinct image used to mutate an upstream tag in the manifestCheckInterval test
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/test-images/busybox:1.36 oci:${TEST_DATA_DIR}/busybox:1.36
    # Setup zot server
    local zot_sync_per_root_dir=${BATS_FILE_TMPDIR}/zot-per
    local zot_sync_ondemand_root_dir=${BATS_FILE_TMPDIR}/zot-ondemand
    local zot_sync_interval_root_dir=${BATS_FILE_TMPDIR}/zot-interval

    local zot_sync_per_config_file=${BATS_FILE_TMPDIR}/zot_sync_per_config.json
    local zot_sync_ondemand_config_file=${BATS_FILE_TMPDIR}/zot_sync_ondemand_config.json
    local zot_sync_interval_config_file=${BATS_FILE_TMPDIR}/zot_sync_interval_config.json

    local zot_minimal_root_dir=${BATS_FILE_TMPDIR}/zot-minimal
    local zot_minimal_config_file=${BATS_FILE_TMPDIR}/zot_minimal_config.json

    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    mkdir -p ${zot_sync_per_root_dir}
    mkdir -p ${zot_sync_ondemand_root_dir}
    mkdir -p ${zot_sync_interval_root_dir}
    mkdir -p ${zot_minimal_root_dir}
    mkdir -p ${oci_data_dir}
    zot_port1=$(get_free_port_for_service "zot1")
    echo ${zot_port1} > ${BATS_FILE_TMPDIR}/zot.port1
    zot_port2=$(get_free_port_for_service "zot2")
    echo ${zot_port2} > ${BATS_FILE_TMPDIR}/zot.port2
    zot_port3=$(get_free_port_for_service "zot3")
    echo ${zot_port3} > ${BATS_FILE_TMPDIR}/zot.port3
    zot_port4=$(get_free_port_for_service "zot4")
    echo ${zot_port4} > ${BATS_FILE_TMPDIR}/zot.port4

    cat >${zot_sync_per_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_sync_per_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port1}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_port3}"
                    ],
                    "onDemand": false,
                    "tlsVerify": false,
                    "PollInterval": "10s",
                    "disableHTTP2": true,
                    "maxIdleConnsPerHost": 20,
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

    cat >${zot_sync_ondemand_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_sync_ondemand_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port2}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_port3}"
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
    cat >${zot_minimal_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_minimal_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port3}"
    },
    "log": {
        "level": "debug"
    }
}
EOF
    cat >${zot_sync_interval_config_file} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_sync_interval_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port4}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_port3}"
                    ],
                    "onDemand": true,
                    "tlsVerify": false,
                    "manifestCheckInterval": "30s",
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
    git -C ${BATS_FILE_TMPDIR} clone https://github.com/project-zot/helm-charts.git

    zot_serve ${ZOT_MINIMAL_PATH} ${zot_minimal_config_file}
    wait_zot_reachable ${zot_port3}

    zot_serve ${ZOT_PATH} ${zot_sync_per_config_file}
    wait_zot_reachable ${zot_port1}

    zot_serve ${ZOT_PATH} ${zot_sync_ondemand_config_file}
    wait_zot_reachable ${zot_port2}

    zot_serve ${ZOT_PATH} ${zot_sync_interval_config_file}
    wait_zot_reachable ${zot_port4}
}

function teardown_file() {
    zot_stop_all
    run rm -rf ${HOME}/.config/notation
}

# sync image
@test "sync golang image periodically" {
    zot_port1=`cat ${BATS_FILE_TMPDIR}/zot.port1`
    zot_port3=`cat ${BATS_FILE_TMPDIR}/zot.port3`
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port3}/golang:1.20
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port3}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]
    run curl http://127.0.0.1:${zot_port1}/v2/_catalog
    run curl http://127.0.0.1:${zot_port3}/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]

    run sleep 20s

    run curl http://127.0.0.1:${zot_port1}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]

    run curl http://127.0.0.1:${zot_port1}/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
}

@test "sync golang image ondemand" {
    zot_port2=`cat ${BATS_FILE_TMPDIR}/zot.port2`
    zot_port3=`cat ${BATS_FILE_TMPDIR}/zot.port3`
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port3}/golang:1.20
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port3}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]

    # sync golang on demand
    run curl http://127.0.0.1:${zot_port2}/v2/golang/manifests/1.20
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:${zot_port3}/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]

    run curl http://127.0.0.1:${zot_port2}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]

    run curl http://127.0.0.1:${zot_port2}/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
}

# returns the manifest digest a registry serves for repo:reference on stdout
function manifest_digest() {
    local url=$1
    curl -s -D - -o /dev/null \
        -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
        "${url}" | grep -i "docker-content-digest" | tr -d '\r' | awk '{print $2}'
}

# manifestCheckInterval: within the interval a locally-present manifest is served without
# re-checking upstream, so a tag mutated upstream is only picked up after the interval elapses.
@test "sync image ondemand honors manifestCheckInterval" {
    zot_port3=`cat ${BATS_FILE_TMPDIR}/zot.port3`
    zot_port4=`cat ${BATS_FILE_TMPDIR}/zot.port4`

    # push image A (golang) upstream under a dedicated repo:tag
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port3}/interval-test:latest
    [ "$status" -eq 0 ]

    digest_a=$(manifest_digest http://127.0.0.1:${zot_port3}/v2/interval-test/manifests/latest)
    [ -n "${digest_a}" ]

    # first on-demand pull contacts upstream and caches image A
    downstream_digest=$(manifest_digest http://127.0.0.1:${zot_port4}/v2/interval-test/manifests/latest)
    [ "${downstream_digest}" = "${digest_a}" ]

    # mutate upstream: overwrite the SAME tag with a different image B (busybox)
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/busybox:1.36 \
        docker://127.0.0.1:${zot_port3}/interval-test:latest
    [ "$status" -eq 0 ]

    digest_b=$(manifest_digest http://127.0.0.1:${zot_port3}/v2/interval-test/manifests/latest)
    [ -n "${digest_b}" ]
    [ "${digest_b}" != "${digest_a}" ]

    # within the interval the downstream must keep serving cached image A (no upstream re-check)
    downstream_digest=$(manifest_digest http://127.0.0.1:${zot_port4}/v2/interval-test/manifests/latest)
    [ "${downstream_digest}" = "${digest_a}" ]

    # wait for manifestCheckInterval (30s) to elapse
    run sleep 40s

    # after the interval the downstream re-checks upstream and serves the updated image B
    downstream_digest=$(manifest_digest http://127.0.0.1:${zot_port4}/v2/interval-test/manifests/latest)
    [ "${downstream_digest}" = "${digest_b}" ]
}

# sync index
@test "sync image index periodically" {
    zot_port1=`cat ${BATS_FILE_TMPDIR}/zot.port1`
    zot_port3=`cat ${BATS_FILE_TMPDIR}/zot.port3`
    # --multi-arch below pushes an image index (containing many images) instead
    # of an image manifest (single image)
    run skopeo --insecure-policy copy --format=oci --dest-tls-verify=false --multi-arch=all \
        docker://public.ecr.aws/docker/library/busybox:latest \
        docker://127.0.0.1:${zot_port3}/busybox:latest
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port3}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[0]') = '"busybox"' ]
    run curl http://127.0.0.1:${zot_port3}/v2/busybox/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]

    run sleep 30s

    run curl http://127.0.0.1:${zot_port1}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[0]') = '"busybox"' ]

    run curl http://127.0.0.1:${zot_port1}/v2/busybox/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

@test "sync image index on demand" {
    zot_port2=`cat ${BATS_FILE_TMPDIR}/zot.port2`
    zot_port3=`cat ${BATS_FILE_TMPDIR}/zot.port3`
    # --multi-arch below pushes an image index (containing many images) instead
    # of an image manifest (single image)
    run skopeo --insecure-policy copy --format=oci --dest-tls-verify=false --multi-arch=all \
        docker://public.ecr.aws/docker/library/busybox:latest \
        docker://127.0.0.1:${zot_port3}/busybox:latest
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port3}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[1]') = '"golang"' ]
    run curl http://127.0.0.1:${zot_port3}/v2/busybox/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]

    # sync busybox index on demand
    run curl http://127.0.0.1:${zot_port2}/v2/busybox/manifests/latest
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:${zot_port2}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[1]') = '"golang"' ]

    run curl http://127.0.0.1:${zot_port2}/v2/busybox/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

# sign signatures
@test "sign/verify with cosign" {
    zot_port3=`cat ${BATS_FILE_TMPDIR}/zot.port3`
    run cosign initialize
    [ "$status" -eq 0 ]
    run cosign generate-key-pair --output-key-prefix "${BATS_FILE_TMPDIR}/cosign-sign-sync-test"
    [ "$status" -eq 0 ]
    run cosign sign --key ${BATS_FILE_TMPDIR}/cosign-sign-sync-test.key localhost:${zot_port3}/golang:1.20 --yes
    [ "$status" -eq 0 ]
    run env COSIGN_EXPERIMENTAL=1 cosign sign --new-bundle-format=true --registry-referrers-mode=oci-1-1 --key ${BATS_FILE_TMPDIR}/cosign-sign-sync-test.key localhost:${zot_port3}/golang:1.20 --yes
    [ "$status" -eq 0 ]
    run cosign verify --key ${BATS_FILE_TMPDIR}/cosign-sign-sync-test.pub localhost:${zot_port3}/golang:1.20
    [ "$status" -eq 0 ]
}

@test "sign/verify with notation" {
    zot_port3=`cat ${BATS_FILE_TMPDIR}/zot.port3`
    run notation cert generate-test "notation-sign-sync-test"
    [ "$status" -eq 0 ]

    local trust_policy_file=/tmp/trustpolicy.json

    cat <<EOF >"${trust_policy_file}"
{
    "version": "1.0",
    "trustPolicies": [
        {
            "name": "notation-sign-sync-test",
            "registryScopes": [ "*" ],
            "signatureVerification": {
                "level" : "strict"
            },
            "trustStores": [ "ca:notation-sign-sync-test" ],
            "trustedIdentities": [
                "*"
            ]
        }
    ]
}
EOF
    run notation policy import --force "${trust_policy_file}"
    [ "$status" -eq 0 ]
    run notation sign --debug --verbose --key "notation-sign-sync-test" --insecure-registry localhost:${zot_port3}/golang:1.20
    [ "$status" -eq 0 ]
    run notation verify --debug --verbose --insecure-registry localhost:${zot_port3}/golang:1.20
    [ "$status" -eq 0 ]
    run notation list --insecure-registry localhost:${zot_port3}/golang:1.20
    [ "$status" -eq 0 ]
}

@test "sync signatures periodically" {
    zot_port1=`cat ${BATS_FILE_TMPDIR}/zot.port1`
    # wait for signatures to be copied (PollInterval is 10s; allow extra margin on slow CI)
    run sleep 15s

    retry_until_success 12 5 notation verify --insecure-registry localhost:${zot_port1}/golang:1.20
    retry_until_success 12 5 cosign verify --key ${BATS_FILE_TMPDIR}/cosign-sign-sync-test.pub localhost:${zot_port1}/golang:1.20
}

@test "sync signatures ondemand" {
    zot_port2=`cat ${BATS_FILE_TMPDIR}/zot.port2`
    run notation verify --insecure-registry localhost:${zot_port2}/golang:1.20
    [ "$status" -eq 0 ]

    run cosign verify --key ${BATS_FILE_TMPDIR}/cosign-sign-sync-test.pub localhost:${zot_port2}/golang:1.20
    [ "$status" -eq 0 ]
}

# sync oras artifacts
@test "push oras artifact periodically" {
    zot_port3=`cat ${BATS_FILE_TMPDIR}/zot.port3`
    echo "{\"name\":\"foo\",\"value\":\"bar\"}" > config.json
    echo "hello world" > artifact.txt
    run oras push --plain-http 127.0.0.1:${zot_port3}/hello-artifact:v2 \
        --config config.json:application/vnd.acme.rocket.config.v1+json artifact.txt:text/plain -d -v
    [ "$status" -eq 0 ]
    rm -f artifact.txt
    rm -f config.json
}

@test "sync oras artifact periodically" {
    zot_port1=`cat ${BATS_FILE_TMPDIR}/zot.port1`
    # wait for oras artifact to be copied
    run sleep 15s
    run oras pull --plain-http 127.0.0.1:${zot_port1}/hello-artifact:v2 -d -v
    [ "$status" -eq 0 ]
    grep -q "hello world" artifact.txt
    rm -f artifact.txt
}

@test "sync oras artifact on demand" {
    zot_port2=`cat ${BATS_FILE_TMPDIR}/zot.port2`
    run oras pull --plain-http 127.0.0.1:${zot_port2}/hello-artifact:v2 -d -v
    [ "$status" -eq 0 ]
    grep -q "hello world" artifact.txt
    rm -f artifact.txt
}

# sync helm chart
@test "push helm chart" {
    zot_port3=`cat ${BATS_FILE_TMPDIR}/zot.port3`
    run helm package ${BATS_FILE_TMPDIR}/helm-charts/charts/zot -d ${BATS_FILE_TMPDIR}
    [ "$status" -eq 0 ]
    local chart_version=$(awk '/version/{printf $2}' ${BATS_FILE_TMPDIR}/helm-charts/charts/zot/Chart.yaml)
    run helm push ${BATS_FILE_TMPDIR}/zot-${chart_version}.tgz oci://localhost:${zot_port3}/zot-chart
    [ "$status" -eq 0 ]
}

@test "sync helm chart periodically" {
    zot_port1=`cat ${BATS_FILE_TMPDIR}/zot.port1`
     # wait for helm chart to be copied
    run sleep 15s

    local chart_version=$(awk '/version/{printf $2}' ${BATS_FILE_TMPDIR}/helm-charts/charts/zot/Chart.yaml)
    run helm pull oci://localhost:${zot_port1}/zot-chart/zot --version ${chart_version} -d ${BATS_FILE_TMPDIR}
    [ "$status" -eq 0 ]
}

@test "sync helm chart on demand" {
    zot_port2=`cat ${BATS_FILE_TMPDIR}/zot.port2`
    local chart_version=$(awk '/version/{printf $2}' ${BATS_FILE_TMPDIR}/helm-charts/charts/zot/Chart.yaml)
    run helm pull oci://localhost:${zot_port2}/zot-chart/zot --version ${chart_version} -d ${BATS_FILE_TMPDIR}
    [ "$status" -eq 0 ]
}

# sync OCI artifacts
@test "push OCI artifact (oci image mediatype) with regclient" {
    zot_port1=`cat ${BATS_FILE_TMPDIR}/zot.port1`
    zot_port2=`cat ${BATS_FILE_TMPDIR}/zot.port2`
    zot_port3=`cat ${BATS_FILE_TMPDIR}/zot.port3`
    run regctl registry set localhost:${zot_port3} --tls disabled
    run regctl registry set localhost:${zot_port1} --tls disabled
    run regctl registry set localhost:${zot_port2} --tls disabled

    run regctl artifact put localhost:${zot_port3}/artifact:demo <<EOF
this is an oci image artifact
EOF
    [ "$status" -eq 0 ]
}

@test "sync OCI artifact (oci image mediatype) periodically" {
    zot_port1=`cat ${BATS_FILE_TMPDIR}/zot.port1`
    # wait for helm chart to be copied
    run sleep 15s
    run regctl manifest get localhost:${zot_port1}/artifact:demo
    [ "$status" -eq 0 ]
    run regctl artifact get localhost:${zot_port1}/artifact:demo
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" == "this is an oci image artifact" ]
}

@test "sync OCI artifact (oci image mediatype) on demand" {
    zot_port2=`cat ${BATS_FILE_TMPDIR}/zot.port2`
    run regctl manifest get localhost:${zot_port2}/artifact:demo
    [ "$status" -eq 0 ]
    run regctl artifact get localhost:${zot_port2}/artifact:demo
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" == "this is an oci image artifact" ]
}

@test "push OCI artifact (oci artifact mediatype) with regclient" {
    zot_port3=`cat ${BATS_FILE_TMPDIR}/zot.port3`
    run regctl artifact put --artifact-type "application/vnd.example.icecream.v1"  localhost:${zot_port3}/newartifact:demo <<EOF
this is an oci artifact
EOF
    [ "$status" -eq 0 ]
}

@test "sync OCI artifact (oci artifact mediatype) periodically" {
    zot_port1=`cat ${BATS_FILE_TMPDIR}/zot.port1`
    # wait for helm chart to be copied
    run sleep 15s
    run regctl manifest get localhost:${zot_port1}/newartifact:demo
    [ "$status" -eq 0 ]
    run regctl artifact get localhost:${zot_port1}/newartifact:demo
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" == "this is an oci artifact" ]
}

@test "sync OCI artifact (oci artifact mediatype) on demand" {
    zot_port2=`cat ${BATS_FILE_TMPDIR}/zot.port2`
    run regctl manifest get localhost:${zot_port2}/newartifact:demo
    [ "$status" -eq 0 ]
    run regctl artifact get localhost:${zot_port2}/newartifact:demo
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" == "this is an oci artifact" ]
}

@test "push OCI artifact references with regclient" {
    zot_port3=`cat ${BATS_FILE_TMPDIR}/zot.port3`
    run regctl artifact put localhost:${zot_port3}/manifest-ref:demo <<EOF
test artifact
EOF
    [ "$status" -eq 0 ]
    run regctl artifact list localhost:${zot_port3}/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
    run regctl artifact put --annotation  demo=true --annotation format=oci --artifact-type "application/vnd.example.icecream.v1" --subject localhost:${zot_port3}/manifest-ref:demo << EOF
test reference
EOF
    [ "$status" -eq 0 ]
    # with artifact media-type
    run regctl artifact put localhost:${zot_port3}/artifact-ref:demo <<EOF
test artifact
EOF
    [ "$status" -eq 0 ]
    run regctl artifact list localhost:${zot_port3}/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
    run regctl artifact put --annotation  demo=true --annotation format=oci --artifact-type "application/vnd.example.icecream.v1" --subject localhost:${zot_port3}/artifact-ref:demo << EOF
test reference
EOF
    [ "$status" -eq 0 ]
}

@test "sync OCI artifact references periodically" {
    zot_port1=`cat ${BATS_FILE_TMPDIR}/zot.port1`
    # wait for OCI artifacts to be copied
    run sleep 20
    run regctl artifact get localhost:${zot_port1}/manifest-ref:demo
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" == "test artifact" ]
    run regctl artifact list localhost:${zot_port1}/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/vnd.example.icecream.v1" localhost:${zot_port1}/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/invalid" localhost:${zot_port1}/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
    # with artifact media-type
    run regctl artifact get localhost:${zot_port1}/artifact-ref:demo
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" == "test artifact" ]
    run regctl artifact list localhost:${zot_port1}/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/vnd.example.icecream.v1" localhost:${zot_port1}/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/invalid" localhost:${zot_port1}/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
}

@test "sync OCI artifact references on demand" {
    zot_port2=`cat ${BATS_FILE_TMPDIR}/zot.port2`
    run regctl artifact get localhost:${zot_port2}/manifest-ref:demo
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" == "test artifact" ]
    run regctl artifact list localhost:${zot_port2}/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/vnd.example.icecream.v1" localhost:${zot_port2}/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/invalid" localhost:${zot_port2}/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
    # with artifact media-type
    run regctl artifact get localhost:${zot_port2}/artifact-ref:demo
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" == "test artifact" ]
    run regctl artifact list localhost:${zot_port2}/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/vnd.example.icecream.v1" localhost:${zot_port2}/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/invalid" localhost:${zot_port2}/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
}
