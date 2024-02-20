# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_wait


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

function setup_file() {
    export COSIGN_PASSWORD=""
    export COSIGN_OCI_EXPERIMENTAL=1
    export COSIGN_EXPERIMENTAL=1

    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20
    # Setup zot server
    local zot_sync_per_root_dir=${BATS_FILE_TMPDIR}/zot-per
    local zot_sync_ondemand_root_dir=${BATS_FILE_TMPDIR}/zot-ondemand

    local zot_sync_per_config_file=${BATS_FILE_TMPDIR}/zot_sync_per_config.json
    local zot_sync_ondemand_config_file=${BATS_FILE_TMPDIR}/zot_sync_ondemand_config.json

    local zot_minimal_root_dir=${BATS_FILE_TMPDIR}/zot-minimal
    local zot_minimal_config_file=${BATS_FILE_TMPDIR}/zot_minimal_config.json

    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    mkdir -p ${zot_sync_per_root_dir}
    mkdir -p ${zot_sync_ondemand_root_dir}
    mkdir -p ${zot_minimal_root_dir}
    mkdir -p ${oci_data_dir}
    zot_port1=$(get_free_port)
    echo ${zot_port1} > ${BATS_FILE_TMPDIR}/zot.port1
    zot_port2=$(get_free_port)
    echo ${zot_port2} > ${BATS_FILE_TMPDIR}/zot.port2
    zot_port3=$(get_free_port)
    echo ${zot_port3} > ${BATS_FILE_TMPDIR}/zot.port3

    cat >${zot_sync_per_config_file} <<EOF
{
    "distSpecVersion": "1.1.0",
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
    "distSpecVersion": "1.1.0",
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
    "distSpecVersion": "1.1.0",
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
    git -C ${BATS_FILE_TMPDIR} clone https://github.com/project-zot/helm-charts.git

    zot_serve ${ZOT_MINIMAL_PATH} ${zot_minimal_config_file}
    wait_zot_reachable ${zot_port3}

    zot_serve ${ZOT_PATH} ${zot_sync_per_config_file}
    wait_zot_reachable ${zot_port1}

    zot_serve ${ZOT_PATH} ${zot_sync_ondemand_config_file}
    wait_zot_reachable ${zot_port2}
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
    run cosign sign --registry-referrers-mode=oci-1-1 --key ${BATS_FILE_TMPDIR}/cosign-sign-sync-test.key localhost:${zot_port3}/golang:1.20 --yes
    [ "$status" -eq 0 ]
    run cosign verify --key ${BATS_FILE_TMPDIR}/cosign-sign-sync-test.pub localhost:${zot_port3}/golang:1.20
    [ "$status" -eq 0 ]
}

@test "sign/verify with notation" {
    zot_port3=`cat ${BATS_FILE_TMPDIR}/zot.port3`
    run notation cert generate-test "notation-sign-sync-test"
    [ "$status" -eq 0 ]

    local trust_policy_file=${HOME}/.config/notation/trustpolicy.json

    cat >${trust_policy_file} <<EOF
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

    run notation sign --key "notation-sign-sync-test" --insecure-registry localhost:${zot_port3}/golang:1.20
    [ "$status" -eq 0 ]
    run notation verify --insecure-registry localhost:${zot_port3}/golang:1.20
    [ "$status" -eq 0 ]
    run notation list --insecure-registry localhost:${zot_port3}/golang:1.20
    [ "$status" -eq 0 ]
}

@test "sync signatures periodically" {
    zot_port1=`cat ${BATS_FILE_TMPDIR}/zot.port1`
    # wait for signatures to be copied
    run sleep 15s

    run notation verify --insecure-registry localhost:${zot_port1}/golang:1.20
    [ "$status" -eq 0 ]

    run cosign verify --key ${BATS_FILE_TMPDIR}/cosign-sign-sync-test.pub localhost:${zot_port1}/golang:1.20
    [ "$status" -eq 0 ]
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
