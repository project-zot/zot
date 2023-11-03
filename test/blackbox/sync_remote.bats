# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_wait
load helpers_cloud


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

    cat >${zot_sync_per_config_file} <<EOF
{
    "distSpecVersion": "1.1.0-dev",
    "storage": {
        "rootDirectory": "${zot_sync_per_root_dir}",
        "dedupe": false,
        "remoteCache": false,
        "storageDriver": {
            "name": "s3",
            "rootdirectory": "/zot",
            "region": "us-east-2",
            "regionendpoint": "localhost:4566",
            "bucket": "zot-storage",
            "secure": false,
            "skipverify": false
        }
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8081"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:9000"
                    ],
                    "onDemand": false,
                    "tlsVerify": false,
                    "PollInterval": "1s",
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
    "distSpecVersion": "1.1.0-dev",
    "storage": {
        "rootDirectory": "${zot_sync_ondemand_root_dir}"
        "dedupe": false,
        "remoteCache": false,
        "storageDriver": {
            "name": "s3",
            "rootdirectory": "/zot",
            "region": "us-east-2",
            "regionendpoint": "localhost:4566",
            "bucket": "zot-storage",
            "secure": false,
            "skipverify": false
        },
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8082"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:9000"
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
    "distSpecVersion": "1.1.0-dev",
    "storage": {
        "rootDirectory": "${zot_minimal_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "9000"
    },
    "log": {
        "level": "debug"
    }
}
EOF
git -C ${BATS_FILE_TMPDIR} clone https://github.com/project-zot/helm-charts.git

zot_serve ${ZOT_PATH} ${zot_sync_per_config_file}
wait_zot_reachable 8081

zot_serve ${ZOT_PATH} ${zot_sync_ondemand_config_file}
wait_zot_reachable 8082

zot_serve ${ZOT_MINIMAL_PATH} ${zot_minimal_config_file}
wait_zot_reachable 9000
}

function teardown_file() {
    zot_stop_all
    run rm -rf ${HOME}/.config/notation
}

# sync image
@test "sync golang image periodically" {
run skopeo --insecure-policy copy --dest-tls-verify=false \
    oci:${TEST_DATA_DIR}/golang:1.20 \
    docker://127.0.0.1:9000/golang:1.20
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:9000/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]
    run curl http://127.0.0.1:8081/v2/_catalog
    run curl http://127.0.0.1:9000/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]

    run sleep 20s

    run curl http://127.0.0.1:8081/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]

    run curl http://127.0.0.1:8081/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
}

@test "sync golang image ondemand" {
run skopeo --insecure-policy copy --dest-tls-verify=false \
    oci:${TEST_DATA_DIR}/golang:1.20 \
    docker://127.0.0.1:9000/golang:1.20
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:9000/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]

    # sync golang on demand
    run curl http://127.0.0.1:8082/v2/golang/manifests/1.20
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:9000/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]

    run curl http://127.0.0.1:8082/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]

    run curl http://127.0.0.1:8082/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
}

# sync index
@test "sync image index periodically" {
# --multi-arch below pushes an image index (containing many images) instead
# of an image manifest (single image)
run skopeo --insecure-policy copy --format=oci --dest-tls-verify=false --multi-arch=all \
    docker://public.ecr.aws/docker/library/busybox:latest \
    docker://127.0.0.1:9000/busybox:latest
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:9000/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[0]') = '"busybox"' ]
    run curl http://127.0.0.1:9000/v2/busybox/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]

    run sleep 30s

    run curl http://127.0.0.1:8081/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[0]') = '"busybox"' ]

    run curl http://127.0.0.1:8081/v2/busybox/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

@test "sync image index on demand" {
# --multi-arch below pushes an image index (containing many images) instead
# of an image manifest (single image)
run skopeo --insecure-policy copy --format=oci --dest-tls-verify=false --multi-arch=all \
    docker://public.ecr.aws/docker/library/busybox:latest \
    docker://127.0.0.1:9000/busybox:latest
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:9000/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[1]') = '"golang"' ]
    run curl http://127.0.0.1:9000/v2/busybox/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]

    # sync busybox index on demand
    run curl http://127.0.0.1:8082/v2/busybox/manifests/latest
    [ "$status" -eq 0 ]

    run curl http://127.0.0.1:8082/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[1]') = '"golang"' ]

    run curl http://127.0.0.1:8082/v2/busybox/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

# sign signatures
@test "sign/verify with cosign" {
run cosign initialize
[ "$status" -eq 0 ]
run cosign generate-key-pair --output-key-prefix "${BATS_FILE_TMPDIR}/cosign-sign-sync-test"
[ "$status" -eq 0 ]
run cosign sign --key ${BATS_FILE_TMPDIR}/cosign-sign-sync-test.key localhost:9000/golang:1.20 --yes
[ "$status" -eq 0 ]
run cosign sign --registry-referrers-mode=oci-1-1 --key ${BATS_FILE_TMPDIR}/cosign-sign-sync-test.key localhost:9000/golang:1.20 --yes
[ "$status" -eq 0 ]
run cosign verify --key ${BATS_FILE_TMPDIR}/cosign-sign-sync-test.pub localhost:9000/golang:1.20
[ "$status" -eq 0 ]
}

@test "sign/verify with notation" {
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

run notation sign --key "notation-sign-sync-test" --insecure-registry localhost:9000/golang:1.20
[ "$status" -eq 0 ]
run notation verify --insecure-registry localhost:9000/golang:1.20
[ "$status" -eq 0 ]
run notation list --insecure-registry localhost:9000/golang:1.20
[ "$status" -eq 0 ]
}

@test "sync signatures periodically" {
# wait for signatures to be copied
run sleep 15s

run notation verify --insecure-registry localhost:8081/golang:1.20
[ "$status" -eq 0 ]

run cosign verify --key ${BATS_FILE_TMPDIR}/cosign-sign-sync-test.pub localhost:8081/golang:1.20
[ "$status" -eq 0 ]
}

@test "sync signatures ondemand" {
run notation verify --insecure-registry localhost:8082/golang:1.20
[ "$status" -eq 0 ]

run cosign verify --key ${BATS_FILE_TMPDIR}/cosign-sign-sync-test.pub localhost:8082/golang:1.20
[ "$status" -eq 0 ]
}

# sync oras artifacts
@test "push oras artifact periodically" {
echo "{\"name\":\"foo\",\"value\":\"bar\"}" > config.json
echo "hello world" > artifact.txt
run oras push --plain-http 127.0.0.1:9000/hello-artifact:v2 \
    --config config.json:application/vnd.acme.rocket.config.v1+json artifact.txt:text/plain -d -v
    [ "$status" -eq 0 ]
    rm -f artifact.txt
    rm -f config.json
}

@test "sync oras artifact periodically" {
#     # wait for oras artifact to be copied
run sleep 15s
run oras pull --plain-http 127.0.0.1:8081/hello-artifact:v2 -d -v
[ "$status" -eq 0 ]
grep -q "hello world" artifact.txt
rm -f artifact.txt
}

@test "sync oras artifact on demand" {
run oras pull --plain-http 127.0.0.1:8082/hello-artifact:v2 -d -v
[ "$status" -eq 0 ]
grep -q "hello world" artifact.txt
rm -f artifact.txt
}

# sync helm chart
@test "push helm chart" {
run helm package ${BATS_FILE_TMPDIR}/helm-charts/charts/zot -d ${BATS_FILE_TMPDIR}
[ "$status" -eq 0 ]
local chart_version=$(awk '/version/{printf $2}' ${BATS_FILE_TMPDIR}/helm-charts/charts/zot/Chart.yaml)
run helm push ${BATS_FILE_TMPDIR}/zot-${chart_version}.tgz oci://localhost:9000/zot-chart
[ "$status" -eq 0 ]
}

@test "sync helm chart periodically" {
# wait for helm chart to be copied
run sleep 15s

local chart_version=$(awk '/version/{printf $2}' ${BATS_FILE_TMPDIR}/helm-charts/charts/zot/Chart.yaml)
run helm pull oci://localhost:8081/zot-chart/zot --version ${chart_version} -d ${BATS_FILE_TMPDIR}
[ "$status" -eq 0 ]
}

@test "sync helm chart on demand" {
local chart_version=$(awk '/version/{printf $2}' ${BATS_FILE_TMPDIR}/helm-charts/charts/zot/Chart.yaml)
run helm pull oci://localhost:8082/zot-chart/zot --version ${chart_version} -d ${BATS_FILE_TMPDIR}
[ "$status" -eq 0 ]
}

# sync OCI artifacts
@test "push OCI artifact (oci image mediatype) with regclient" {
run regctl registry set localhost:9000 --tls disabled
run regctl registry set localhost:8081 --tls disabled
run regctl registry set localhost:8082 --tls disabled

run regctl artifact put localhost:9000/artifact:demo <<EOF
this is an oci image artifact
EOF
[ "$status" -eq 0 ]
}

@test "sync OCI artifact (oci image mediatype) periodically" {
# wait for helm chart to be copied
run sleep 15s
run regctl manifest get localhost:8081/artifact:demo
[ "$status" -eq 0 ]
run regctl artifact get localhost:8081/artifact:demo
[ "$status" -eq 0 ]
[ "${lines[-1]}" == "this is an oci image artifact" ]
}

@test "sync OCI artifact (oci image mediatype) on demand" {
run regctl manifest get localhost:8082/artifact:demo
[ "$status" -eq 0 ]
run regctl artifact get localhost:8082/artifact:demo
[ "$status" -eq 0 ]
[ "${lines[-1]}" == "this is an oci image artifact" ]
}

@test "push OCI artifact (oci artifact mediatype) with regclient" {
run regctl artifact put --artifact-type "application/vnd.example.icecream.v1"  localhost:9000/newartifact:demo <<EOF
this is an oci artifact
EOF
[ "$status" -eq 0 ]
}

@test "sync OCI artifact (oci artifact mediatype) periodically" {
# wait for helm chart to be copied
run sleep 15s
run regctl manifest get localhost:8081/newartifact:demo
[ "$status" -eq 0 ]
run regctl artifact get localhost:8081/newartifact:demo
[ "$status" -eq 0 ]
[ "${lines[-1]}" == "this is an oci artifact" ]
}

@test "sync OCI artifact (oci artifact mediatype) on demand" {
run regctl manifest get localhost:8082/newartifact:demo
[ "$status" -eq 0 ]
run regctl artifact get localhost:8082/newartifact:demo
[ "$status" -eq 0 ]
[ "${lines[-1]}" == "this is an oci artifact" ]
}

@test "push OCI artifact references with regclient" {
run regctl artifact put localhost:9000/manifest-ref:demo <<EOF
test artifact
EOF
[ "$status" -eq 0 ]
run regctl artifact list localhost:9000/manifest-ref:demo --format raw-body
[ "$status" -eq 0 ]
[ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
run regctl artifact put --annotation  demo=true --annotation format=oci --artifact-type "application/vnd.example.icecream.v1" --subject localhost:9000/manifest-ref:demo << EOF
test reference
EOF
[ "$status" -eq 0 ]
# with artifact media-type
run regctl artifact put localhost:9000/artifact-ref:demo <<EOF
test artifact
EOF
[ "$status" -eq 0 ]
run regctl artifact list localhost:9000/artifact-ref:demo --format raw-body
[ "$status" -eq 0 ]
[ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
run regctl artifact put --annotation  demo=true --annotation format=oci --artifact-type "application/vnd.example.icecream.v1" --subject localhost:9000/artifact-ref:demo << EOF
test reference
EOF
[ "$status" -eq 0 ]
}

@test "sync OCI artifact references periodically" {
# wait for OCI artifacts to be copied
run sleep 20
run regctl artifact get localhost:8081/manifest-ref:demo
[ "$status" -eq 0 ]
[ "${lines[-1]}" == "test artifact" ]
run regctl artifact list localhost:8081/manifest-ref:demo --format raw-body
[ "$status" -eq 0 ]
[ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
run regctl artifact list --filter-artifact-type "application/vnd.example.icecream.v1" localhost:8081/manifest-ref:demo --format raw-body
[ "$status" -eq 0 ]
[ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
run regctl artifact list --filter-artifact-type "application/invalid" localhost:8081/manifest-ref:demo --format raw-body
[ "$status" -eq 0 ]
[ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
# with artifact media-type
run regctl artifact get localhost:8081/artifact-ref:demo
[ "$status" -eq 0 ]
[ "${lines[-1]}" == "test artifact" ]
run regctl artifact list localhost:8081/artifact-ref:demo --format raw-body
[ "$status" -eq 0 ]
[ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
run regctl artifact list --filter-artifact-type "application/vnd.example.icecream.v1" localhost:8081/artifact-ref:demo --format raw-body
[ "$status" -eq 0 ]
[ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
run regctl artifact list --filter-artifact-type "application/invalid" localhost:8081/artifact-ref:demo --format raw-body
[ "$status" -eq 0 ]
[ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
}

@test "sync OCI artifact references on demand" {
run regctl artifact get localhost:8082/manifest-ref:demo
[ "$status" -eq 0 ]
[ "${lines[-1]}" == "test artifact" ]
run regctl artifact list localhost:8082/manifest-ref:demo --format raw-body
[ "$status" -eq 0 ]
[ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
run regctl artifact list --filter-artifact-type "application/vnd.example.icecream.v1" localhost:8082/manifest-ref:demo --format raw-body
[ "$status" -eq 0 ]
[ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
run regctl artifact list --filter-artifact-type "application/invalid" localhost:8082/manifest-ref:demo --format raw-body
[ "$status" -eq 0 ]
[ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
# with artifact media-type
run regctl artifact get localhost:8082/artifact-ref:demo
[ "$status" -eq 0 ]
[ "${lines[-1]}" == "test artifact" ]
run regctl artifact list localhost:8082/artifact-ref:demo --format raw-body
[ "$status" -eq 0 ]
[ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
run regctl artifact list --filter-artifact-type "application/vnd.example.icecream.v1" localhost:8082/artifact-ref:demo --format raw-body
[ "$status" -eq 0 ]
[ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
run regctl artifact list --filter-artifact-type "application/invalid" localhost:8082/artifact-ref:demo --format raw-body
[ "$status" -eq 0 ]
[ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
}
