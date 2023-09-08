# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot

function verify_prerequisites {
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
    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi
    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20
    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    mkdir -p ${zot_root_dir}
    mkdir -p ${oci_data_dir}
    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.0-dev",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8080"
    },
    "log": {
        "level": "debug",
        "output": "${BATS_FILE_TMPDIR}/zot.log"
    }
}
EOF
    git -C ${BATS_FILE_TMPDIR} clone https://github.com/project-zot/helm-charts.git
    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable 8080
}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot.log
}

function teardown_file() {
    zot_stop_all
}

@test "push image" {
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:8080/golang:1.20
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:8080/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]
    run curl http://127.0.0.1:8080/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
}

@test "pull image" {
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:8080/golang:1.20 \
        oci:${oci_data_dir}/golang:1.20
    [ "$status" -eq 0 ]
    run cat ${BATS_FILE_TMPDIR}/oci/golang/index.json
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].annotations."org.opencontainers.image.ref.name"') = '"1.20"' ]
}

@test "push image index" {
    # --multi-arch below pushes an image index (containing many images) instead
    # of an image manifest (single image)
    run skopeo --insecure-policy copy --format=oci --dest-tls-verify=false --multi-arch=all \
        docker://public.ecr.aws/docker/library/busybox:latest \
        docker://127.0.0.1:8080/busybox:latest
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:8080/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[0]') = '"busybox"' ]
    run curl http://127.0.0.1:8080/v2/busybox/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

@test "pull image index" {
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    run skopeo --insecure-policy copy --src-tls-verify=false --multi-arch=all \
        docker://127.0.0.1:8080/busybox:latest \
        oci:${oci_data_dir}/busybox:latest
    [ "$status" -eq 0 ]
    run cat ${BATS_FILE_TMPDIR}/oci/busybox/index.json
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].annotations."org.opencontainers.image.ref.name"') = '"latest"' ]
    run skopeo --insecure-policy --override-arch=arm64 --override-os=linux copy --src-tls-verify=false --multi-arch=all \
        docker://127.0.0.1:8080/busybox:latest \
        oci:${oci_data_dir}/busybox:latest
    [ "$status" -eq 0 ]
    run cat ${BATS_FILE_TMPDIR}/oci/busybox/index.json
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].annotations."org.opencontainers.image.ref.name"') = '"latest"' ]
    run curl -X DELETE http://127.0.0.1:8080/v2/busybox/manifests/latest
    [ "$status" -eq 0 ]
}

@test "push oras artifact" {
    echo "{\"name\":\"foo\",\"value\":\"bar\"}" > config.json
    echo "hello world" > artifact.txt
    run oras push --plain-http 127.0.0.1:8080/hello-artifact:v2 \
        --config config.json:application/vnd.acme.rocket.config.v1+json artifact.txt:text/plain -d -v
    [ "$status" -eq 0 ]
    rm -f artifact.txt
    rm -f config.json
}

@test "pull oras artifact" {
    run oras pull --plain-http 127.0.0.1:8080/hello-artifact:v2 -d -v
    [ "$status" -eq 0 ]
    grep -q "hello world" artifact.txt
    rm -f artifact.txt
}

@test "attach oras artifacts" {
    # attach signature
    echo "{\"artifact\": \"\", \"signature\": \"pat hancock\"}" > ${BATS_FILE_TMPDIR}/signature.json
    run oras attach --plain-http 127.0.0.1:8080/golang:1.20 --image-spec v1.1-image --artifact-type 'signature/example' ${BATS_FILE_TMPDIR}/signature.json:application/json
    [ "$status" -eq 0 ]
    # attach sbom
    echo "{\"version\": \"0.0.0.0\", \"artifact\": \"'127.0.0.1:8080/golang:1.20'\", \"contents\": \"good\"}" > ${BATS_FILE_TMPDIR}/sbom.json
    run oras attach --plain-http 127.0.0.1:8080/golang:1.20 --image-spec v1.1-image --artifact-type 'sbom/example' ${BATS_FILE_TMPDIR}/sbom.json:application/json
    [ "$status" -eq 0 ]
}

@test "discover oras artifacts" {
    run oras discover --plain-http -o json 127.0.0.1:8080/golang:1.20
    [ "$status" -eq 0 ]
    [ $(echo "$output" | jq -r ".manifests | length") -eq 2 ]
}

@test "add and list tags using oras" {
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:8080/oras-tags:1.20
    [ "$status" -eq 0 ]
    run oras tag --plain-http 127.0.0.1:8080/oras-tags:1.20 1 new latest
    [ "$status" -eq 0 ]
    run oras repo tags --plain-http 127.0.0.1:8080/oras-tags
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 4 ]
    [ "${lines[-1]}" == "new" ]
    [ "${lines[-2]}" == "latest" ]
    [ "${lines[-3]}" == "1.20" ]
    [ "${lines[-4]}" == "1" ]
    run oras repo tags --plain-http --last new 127.0.0.1:8080/oras-tags
    [ "$status" -eq 0 ]
    echo "$output"
    [ -z $output ]
    run oras repo tags --plain-http --last latest 127.0.0.1:8080/oras-tags
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 1 ]
    [ "${lines[-1]}" == "new" ]
    run oras repo tags --plain-http --last "1.20" 127.0.0.1:8080/oras-tags
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 2 ]
    [ "${lines[-2]}" == "latest" ]
    [ "${lines[-1]}" == "new" ]
    run oras repo tags --plain-http --last "1" 127.0.0.1:8080/oras-tags
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 3 ]
    [ "${lines[-3]}" == "1.20" ]
    [ "${lines[-2]}" == "latest" ]
    [ "${lines[-1]}" == "new" ]
}

@test "push helm chart" {
    run helm package ${BATS_FILE_TMPDIR}/helm-charts/charts/zot -d ${BATS_FILE_TMPDIR}
    [ "$status" -eq 0 ]
    local chart_version=$(awk '/version/{printf $2}' ${BATS_FILE_TMPDIR}/helm-charts/charts/zot/Chart.yaml)
    run helm push ${BATS_FILE_TMPDIR}/zot-${chart_version}.tgz oci://localhost:8080/zot-chart
    [ "$status" -eq 0 ]
}

@test "pull helm chart" {
    local chart_version=$(awk '/version/{printf $2}' ${BATS_FILE_TMPDIR}/helm-charts/charts/zot/Chart.yaml)
    run helm pull oci://localhost:8080/zot-chart/zot --version ${chart_version} -d ${BATS_FILE_TMPDIR}
    [ "$status" -eq 0 ]
}

@test "push image with regclient" {
    run regctl registry set localhost:8080 --tls disabled
    [ "$status" -eq 0 ]
    run regctl image copy ocidir://${TEST_DATA_DIR}/golang:1.20 localhost:8080/test-regclient
    [ "$status" -eq 0 ]
}

@test "pull image with regclient" {
    run regctl image copy localhost:8080/test-regclient ocidir://${TEST_DATA_DIR}/golang:1.20
    [ "$status" -eq 0 ]
}

@test "list repositories with regclient" {
    run regctl repo ls localhost:8080
    [ "$status" -eq 0 ]

    found=0
    for i in "${lines[@]}"
    do

        if [ "$i" = 'test-regclient' ]; then
            found=1
        fi
    done
    [ "$found" -eq 1 ]
}

@test "list image tags with regclient" {
    run regctl tag ls localhost:8080/test-regclient
    [ "$status" -eq 0 ]

    found=0
    for i in "${lines[@]}"
    do

        if [ "$i" = 'latest' ]; then
            found=1
        fi
    done
    [ "$found" -eq 1 ]
}

@test "push manifest with regclient" {
    manifest=$(regctl manifest get localhost:8080/test-regclient --format=raw-body)
    run regctl manifest put localhost:8080/test-regclient:1.0.0 --format oci --content-type application/vnd.oci.image.manifest.v1+json --format oci <<EOF
    $manifest
EOF
    [ "$status" -eq 0 ]
}

@test "pull manifest with regclient" {
    run regctl manifest get localhost:8080/test-regclient
    [ "$status" -eq 0 ]
}

@test "pull manifest with docker client" {
    run docker pull localhost:8080/test-regclient
    [ "$status" -eq 0 ]
}

@test "pull manifest with crictl" {
    run crictl pull localhost:8080/test-regclient
    [ "$status" -eq 0 ]
}

@test "push OCI artifact with regclient" {
    run regctl artifact put localhost:8080/artifact:demo <<EOF
this is an artifact
EOF
    [ "$status" -eq 0 ]
}

@test "pull OCI artifact with regclient" {
    run regctl manifest get localhost:8080/artifact:demo
    [ "$status" -eq 0 ]
    run regctl artifact get localhost:8080/artifact:demo
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" == "this is an artifact" ]
}

@test "push OCI artifact references with regclient" {
    run regctl artifact put localhost:8080/manifest-ref:demo <<EOF
test artifact
EOF
    [ "$status" -eq 0 ]
    run regctl artifact list localhost:8080/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
    run regctl artifact put --annotation  demo=true --annotation format=oci --artifact-type "application/vnd.example.icecream.v1" --subject localhost:8080/manifest-ref:demo << EOF
test reference
EOF
    [ "$status" -eq 0 ]
    # with artifact media-type
    run regctl artifact put localhost:8080/artifact-ref:demo <<EOF
test artifact
EOF
    [ "$status" -eq 0 ]
    run regctl artifact list localhost:8080/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
    run regctl artifact put --annotation  demo=true --annotation format=oci --artifact-type "application/vnd.example.icecream.v1" --subject localhost:8080/artifact-ref:demo << EOF
test reference
EOF
    [ "$status" -eq 0 ]
}

@test "pull OCI artifact references with regclient" {
    run regctl artifact list localhost:8080/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/vnd.example.icecream.v1" localhost:8080/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/invalid" localhost:8080/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
    # with artifact media-type
    run regctl artifact list localhost:8080/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/vnd.example.icecream.v1" localhost:8080/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/invalid" localhost:8080/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
}
