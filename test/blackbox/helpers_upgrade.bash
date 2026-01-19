# Common helper functions and test utilities for upgrade tests
# Used by upgrade.bats and upgrade_minimal.bats

# Verify prerequisites for upgrade tests
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

# Common teardown function - prints zot log on failure
function teardown() {
    # conditionally printing on failure is possible from teardown but not from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot.log
}

# Common teardown_file function - stops all zot instances
function teardown_file() {
    zot_stop_all
}

# ==============================================================================
# RELEASE TEST FUNCTIONS
# These functions are used to test the released version of zot before upgrade
# ==============================================================================

function test_release_push_image() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]
    run curl http://127.0.0.1:${zot_port}/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
}

function test_release_pull_image() {
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:${zot_port}/golang:1.20 \
        oci:${oci_data_dir}/golang:1.20
    [ "$status" -eq 0 ]
    run cat ${BATS_FILE_TMPDIR}/oci/golang/index.json
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].annotations."org.opencontainers.image.ref.name"') = '"1.20"' ]
}

function test_release_push_image_index() {
    # --multi-arch below pushes an image index (containing many images) instead
    # of an image manifest (single image)
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --format=oci --dest-tls-verify=false --multi-arch=all \
        docker://public.ecr.aws/docker/library/busybox:latest \
        docker://127.0.0.1:${zot_port}/busybox:latest
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[0]') = '"busybox"' ]
    run curl http://127.0.0.1:${zot_port}/v2/busybox/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

function test_release_pull_image_index() {
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --src-tls-verify=false --multi-arch=all \
        docker://127.0.0.1:${zot_port}/busybox:latest \
        oci:${oci_data_dir}/busybox:latest
    [ "$status" -eq 0 ]
    run cat ${BATS_FILE_TMPDIR}/oci/busybox/index.json
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].annotations."org.opencontainers.image.ref.name"') = '"latest"' ]
    run skopeo --insecure-policy --override-arch=arm64 --override-os=linux copy --src-tls-verify=false --multi-arch=all \
        docker://127.0.0.1:${zot_port}/busybox:latest \
        oci:${oci_data_dir}/busybox:latest
    [ "$status" -eq 0 ]
    run cat ${BATS_FILE_TMPDIR}/oci/busybox/index.json
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].annotations."org.opencontainers.image.ref.name"') = '"latest"' ]
}

function test_release_push_oras_artifact() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    echo "{\"name\":\"foo\",\"value\":\"bar\"}" > config.json
    echo "hello world" > artifact.txt
    run oras push --plain-http 127.0.0.1:${zot_port}/hello-artifact:v2 \
        --config config.json:application/vnd.acme.rocket.config.v1+json artifact.txt:text/plain -d -v
    [ "$status" -eq 0 ]
    rm -f artifact.txt
    rm -f config.json
}

function test_release_pull_oras_artifact() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run oras pull --plain-http 127.0.0.1:${zot_port}/hello-artifact:v2 -d -v
    [ "$status" -eq 0 ]
    grep -q "hello world" artifact.txt
    rm -f artifact.txt
}

function test_release_attach_oras_artifacts() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    # attach signature
    echo "{\"artifact\": \"\", \"signature\": \"pat hancock\"}" > ${BATS_FILE_TMPDIR}/signature.json
    run oras attach --disable-path-validation --plain-http 127.0.0.1:${zot_port}/golang:1.20 --artifact-type 'signature/example' ${BATS_FILE_TMPDIR}/signature.json:application/json
    [ "$status" -eq 0 ]
    # attach sbom
    echo "{\"version\": \"0.0.0.0\", \"artifact\": \"'127.0.0.1:${zot_port}/golang:1.20'\", \"contents\": \"good\"}" > ${BATS_FILE_TMPDIR}/sbom.json
    run oras attach --disable-path-validation --plain-http 127.0.0.1:${zot_port}/golang:1.20 --artifact-type 'sbom/example' ${BATS_FILE_TMPDIR}/sbom.json:application/json
    [ "$status" -eq 0 ]
}

function test_release_discover_oras_artifacts() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run oras discover --plain-http --format json 127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 0 ]
    [ $(echo "$output" | jq -r ".manifests | length") -eq 2 ]
}

function test_release_add_and_list_tags_using_oras() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/oras-tags:1.20
    [ "$status" -eq 0 ]
    run oras tag --plain-http 127.0.0.1:${zot_port}/oras-tags:1.20 1 new latest
    [ "$status" -eq 0 ]
    run oras repo tags --plain-http 127.0.0.1:${zot_port}/oras-tags
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 4 ]
    [ "${lines[-1]}" == "new" ]
    [ "${lines[-2]}" == "latest" ]
    [ "${lines[-3]}" == "1.20" ]
    [ "${lines[-4]}" == "1" ]
    run oras repo tags --plain-http --last new 127.0.0.1:${zot_port}/oras-tags
    [ "$status" -eq 0 ]
    echo "$output"
    [ -z "$output" ]
    run oras repo tags --plain-http --last latest 127.0.0.1:${zot_port}/oras-tags
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 1 ]
    [ "${lines[-1]}" == "new" ]
    run oras repo tags --plain-http --last "1.20" 127.0.0.1:${zot_port}/oras-tags
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 2 ]
    [ "${lines[-2]}" == "latest" ]
    [ "${lines[-1]}" == "new" ]
    run oras repo tags --plain-http --last "1" 127.0.0.1:${zot_port}/oras-tags
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 3 ]
    [ "${lines[-3]}" == "1.20" ]
    [ "${lines[-2]}" == "latest" ]
    [ "${lines[-1]}" == "new" ]
}

function test_release_push_helm_chart() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run helm package ${BATS_FILE_TMPDIR}/helm-charts/charts/zot -d ${BATS_FILE_TMPDIR}
    [ "$status" -eq 0 ]
    local chart_version=$(awk '/version/{printf $2}' ${BATS_FILE_TMPDIR}/helm-charts/charts/zot/Chart.yaml)
    run helm push ${BATS_FILE_TMPDIR}/zot-${chart_version}.tgz oci://localhost:${zot_port}/zot-chart
    [ "$status" -eq 0 ]
}

function test_release_pull_helm_chart() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    local chart_version=$(awk '/version/{printf $2}' ${BATS_FILE_TMPDIR}/helm-charts/charts/zot/Chart.yaml)
    run helm pull oci://localhost:${zot_port}/zot-chart/zot --version ${chart_version} -d ${BATS_FILE_TMPDIR}
    [ "$status" -eq 0 ]
}

function test_release_push_image_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    run regctl image copy ocidir://${TEST_DATA_DIR}/golang:1.20 localhost:${zot_port}/test-regclient
    [ "$status" -eq 0 ]
}

function test_release_pull_image_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl image copy localhost:${zot_port}/test-regclient ocidir://${TEST_DATA_DIR}/golang:1.20
    [ "$status" -eq 0 ]
}

function test_release_list_repositories_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl repo ls localhost:${zot_port}
    [ "$status" -eq 0 ]

    found=0
    for i in "${lines[@]}"
    do

        if [ "$i" = 'test-regclient' ]; then
            found=1
        fi
    done
    [ "$found" -eq 1 ]

    run regctl repo ls --limit 2 localhost:${zot_port}
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 2 ]
    [ "${lines[-2]}" == "busybox" ]
    [ "${lines[-1]}" == "golang" ]

    run regctl repo ls --last busybox --limit 1 localhost:${zot_port}
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 1 ]
    [ "${lines[-1]}" == "golang" ]
}

function test_release_list_image_tags_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl tag ls localhost:${zot_port}/test-regclient
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

function test_release_push_manifest_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    manifest=$(regctl manifest get localhost:${zot_port}/test-regclient --format=raw-body)
    run regctl manifest put localhost:${zot_port}/test-regclient:1.0.0 --format oci --content-type application/vnd.oci.image.manifest.v1+json --format oci <<JSON
    $manifest
JSON
    [ "$status" -eq 0 ]
}

function test_release_pull_manifest_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl manifest get localhost:${zot_port}/test-regclient
    [ "$status" -eq 0 ]
}

function test_release_pull_manifest_with_docker_client() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run docker pull localhost:${zot_port}/test-regclient
    [ "$status" -eq 0 ]
}

function test_release_pull_manifest_with_crictl() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run crictl pull localhost:${zot_port}/test-regclient
    [ "$status" -eq 0 ]
}

function test_release_push_oci_artifact_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl artifact put localhost:${zot_port}/artifact:demo <<TXT
this is an artifact
TXT
    [ "$status" -eq 0 ]
}

function test_release_pull_oci_artifact_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl manifest get localhost:${zot_port}/artifact:demo
    [ "$status" -eq 0 ]
    run regctl artifact get localhost:${zot_port}/artifact:demo
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" == "this is an artifact" ]
}

function test_release_push_oci_artifact_references_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl artifact put localhost:${zot_port}/manifest-ref:demo <<TXT
test artifact
TXT
    [ "$status" -eq 0 ]
    run regctl artifact list localhost:${zot_port}/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
    run regctl artifact put --annotation  demo=true --annotation format=oci --artifact-type "application/vnd.example.icecream.v1" --subject localhost:${zot_port}/manifest-ref:demo << TXT
test reference
TXT
    [ "$status" -eq 0 ]
    # with artifact media-type
    run regctl artifact put localhost:${zot_port}/artifact-ref:demo <<TXT
test artifact
TXT
    [ "$status" -eq 0 ]
    run regctl artifact list localhost:${zot_port}/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
    run regctl artifact put --annotation  demo=true --annotation format=oci --artifact-type "application/vnd.example.icecream.v1" --subject localhost:${zot_port}/artifact-ref:demo << TXT
test reference
TXT
    [ "$status" -eq 0 ]
}

function test_release_pull_oci_artifact_references_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl artifact list localhost:${zot_port}/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/vnd.example.icecream.v1" localhost:${zot_port}/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/invalid" localhost:${zot_port}/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
    # with artifact media-type
    run regctl artifact list localhost:${zot_port}/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/vnd.example.icecream.v1" localhost:${zot_port}/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/invalid" localhost:${zot_port}/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
}

function test_release_push_docker_image() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    cat > Dockerfile <<DOCKERFILE
    FROM ghcr.io/project-zot/test-images/busybox-docker:1.37
    RUN echo "hello world" > /testfile
DOCKERFILE
    docker build -f Dockerfile . -t localhost:${zot_port}/test
    run docker push localhost:${zot_port}/test
    [ "$status" -eq 1 ]
    run docker pull localhost:${zot_port}/test
    [ "$status" -eq 1 ]
}

# ==============================================================================
# NEW (POST-UPGRADE) TEST FUNCTIONS
# These functions are used to test the new version of zot after upgrade
# ==============================================================================

function test_new_existing_pull_image() {
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:${zot_port}/golang:1.20 \
        oci:${oci_data_dir}/golang:1.20
    [ "$status" -eq 0 ]
    run cat ${BATS_FILE_TMPDIR}/oci/golang/index.json
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].annotations."org.opencontainers.image.ref.name"') = '"1.20"' ]
}

function test_new_existing_pull_image_index() {
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --src-tls-verify=false --multi-arch=all \
        docker://127.0.0.1:${zot_port}/busybox:latest \
        oci:${oci_data_dir}/busybox:latest
    [ "$status" -eq 0 ]
    run cat ${BATS_FILE_TMPDIR}/oci/busybox/index.json
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].annotations."org.opencontainers.image.ref.name"') = '"latest"' ]
    run skopeo --insecure-policy --override-arch=arm64 --override-os=linux copy --src-tls-verify=false --multi-arch=all \
        docker://127.0.0.1:${zot_port}/busybox:latest \
        oci:${oci_data_dir}/busybox:latest
    [ "$status" -eq 0 ]
    run cat ${BATS_FILE_TMPDIR}/oci/busybox/index.json
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].annotations."org.opencontainers.image.ref.name"') = '"latest"' ]
}

function test_new_existing_pull_oras_artifact() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run oras pull --plain-http 127.0.0.1:${zot_port}/hello-artifact:v2 -d -v
    [ "$status" -eq 0 ]
    grep -q "hello world" artifact.txt
    rm -f artifact.txt
}

function test_new_push_image() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    # first check existing images
    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq 'any(.repositories[]; . == "golang")') = true ] 
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 0 ]
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        docker://ghcr.io/project-zot/test-images/alpine:3.17.3 \
        docker://127.0.0.1:${zot_port}/alpine:3.17.3
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq 'any(.repositories[]; . == "golang")') = true ] 
    [ $(echo "${lines[-1]}" | jq 'any(.repositories[]; . == "alpine")') = true ] 
    run curl http://127.0.0.1:${zot_port}/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.20"' ]
}

function test_new_pull_image() {
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:${zot_port}/golang:1.20 \
        oci:${oci_data_dir}/golang:1.20
    [ "$status" -eq 0 ]
    run cat ${BATS_FILE_TMPDIR}/oci/golang/index.json
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].annotations."org.opencontainers.image.ref.name"') = '"1.20"' ]
}

function test_new_push_image_index() {
    # --multi-arch below pushes an image index (containing many images) instead
    # of an image manifest (single image)
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --format=oci --dest-tls-verify=false --multi-arch=all \
        docker://public.ecr.aws/docker/library/busybox:latest \
        docker://127.0.0.1:${zot_port}/busybox:latest
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq 'any(.repositories[]; . == "busybox")') = true ] 
    run curl http://127.0.0.1:${zot_port}/v2/busybox/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"latest"' ]
}

function test_new_pull_image_index() {
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --src-tls-verify=false --multi-arch=all \
        docker://127.0.0.1:${zot_port}/busybox:latest \
        oci:${oci_data_dir}/busybox:latest
    [ "$status" -eq 0 ]
    run cat ${BATS_FILE_TMPDIR}/oci/busybox/index.json
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].annotations."org.opencontainers.image.ref.name"') = '"latest"' ]
    run skopeo --insecure-policy --override-arch=arm64 --override-os=linux copy --src-tls-verify=false --multi-arch=all \
        docker://127.0.0.1:${zot_port}/busybox:latest \
        oci:${oci_data_dir}/busybox:latest
    [ "$status" -eq 0 ]
    run cat ${BATS_FILE_TMPDIR}/oci/busybox/index.json
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].annotations."org.opencontainers.image.ref.name"') = '"latest"' ]
    run curl -X DELETE http://127.0.0.1:${zot_port}/v2/busybox/manifests/latest
    [ "$status" -eq 0 ]
}

function test_new_push_oras_artifact() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    echo "{\"name\":\"foo\",\"value\":\"bar\"}" > config.json
    echo "hello world" > artifact.txt
    run oras push --plain-http 127.0.0.1:${zot_port}/hello-artifact:v2 \
        --config config.json:application/vnd.acme.rocket.config.v1+json artifact.txt:text/plain -d -v
    [ "$status" -eq 0 ]
    rm -f artifact.txt
    rm -f config.json
}

function test_new_pull_oras_artifact() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run oras pull --plain-http 127.0.0.1:${zot_port}/hello-artifact:v2 -d -v
    [ "$status" -eq 0 ]
    grep -q "hello world" artifact.txt
    rm -f artifact.txt
}

function test_new_attach_oras_artifacts() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    # attach signature
    echo "{\"artifact\": \"\", \"signature\": \"pat hancock\"}" > ${BATS_FILE_TMPDIR}/signature.json
    run oras attach --disable-path-validation --plain-http 127.0.0.1:${zot_port}/golang:1.20 --artifact-type 'signature/example' ${BATS_FILE_TMPDIR}/signature.json:application/json
    [ "$status" -eq 0 ]
    # attach sbom
    echo "{\"version\": \"0.0.0.0\", \"artifact\": \"'127.0.0.1:${zot_port}/golang:1.20'\", \"contents\": \"good\"}" > ${BATS_FILE_TMPDIR}/sbom.json
    run oras attach --disable-path-validation --plain-http 127.0.0.1:${zot_port}/golang:1.20 --artifact-type 'sbom/example' ${BATS_FILE_TMPDIR}/sbom.json:application/json
    [ "$status" -eq 0 ]
}

# Note: expected_count parameter allows different counts for full vs minimal zot
function test_new_discover_oras_artifacts() {
    local expected_count=${1:-4}
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run oras discover --plain-http --format json 127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 0 ]
    [ $(echo "$output" | jq -r ".manifests | length") -eq ${expected_count} ]
}

function test_new_add_and_list_tags_using_oras() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/oras-tags:1.20
    [ "$status" -eq 0 ]
    run oras tag --plain-http 127.0.0.1:${zot_port}/oras-tags:1.20 1 new latest
    [ "$status" -eq 0 ]
    run oras repo tags --plain-http 127.0.0.1:${zot_port}/oras-tags
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 4 ]
    [ "${lines[-1]}" == "new" ]
    [ "${lines[-2]}" == "latest" ]
    [ "${lines[-3]}" == "1.20" ]
    [ "${lines[-4]}" == "1" ]
    run oras repo tags --plain-http --last new 127.0.0.1:${zot_port}/oras-tags
    [ "$status" -eq 0 ]
    echo "$output"
    [ -z "$output" ]
    run oras repo tags --plain-http --last latest 127.0.0.1:${zot_port}/oras-tags
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 1 ]
    [ "${lines[-1]}" == "new" ]
    run oras repo tags --plain-http --last "1.20" 127.0.0.1:${zot_port}/oras-tags
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 2 ]
    [ "${lines[-2]}" == "latest" ]
    [ "${lines[-1]}" == "new" ]
    run oras repo tags --plain-http --last "1" 127.0.0.1:${zot_port}/oras-tags
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 3 ]
    [ "${lines[-3]}" == "1.20" ]
    [ "${lines[-2]}" == "latest" ]
    [ "${lines[-1]}" == "new" ]
}

function test_new_push_helm_chart() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run helm package ${BATS_FILE_TMPDIR}/helm-charts/charts/zot -d ${BATS_FILE_TMPDIR}
    [ "$status" -eq 0 ]
    local chart_version=$(awk '/version/{printf $2}' ${BATS_FILE_TMPDIR}/helm-charts/charts/zot/Chart.yaml)
    run helm push ${BATS_FILE_TMPDIR}/zot-${chart_version}.tgz oci://localhost:${zot_port}/zot-chart
    [ "$status" -eq 0 ]
}

function test_new_pull_helm_chart() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    local chart_version=$(awk '/version/{printf $2}' ${BATS_FILE_TMPDIR}/helm-charts/charts/zot/Chart.yaml)
    run helm pull oci://localhost:${zot_port}/zot-chart/zot --version ${chart_version} -d ${BATS_FILE_TMPDIR}
    [ "$status" -eq 0 ]
}

function test_new_push_image_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    run regctl image copy ocidir://${TEST_DATA_DIR}/golang:1.20 localhost:${zot_port}/test-regclient
    [ "$status" -eq 0 ]
}

function test_new_pull_image_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl image copy localhost:${zot_port}/test-regclient ocidir://${TEST_DATA_DIR}/golang:1.20
    [ "$status" -eq 0 ]
}

function test_new_list_repositories_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl repo ls localhost:${zot_port}
    [ "$status" -eq 0 ]

    found=0
    for i in "${lines[@]}"
    do

        if [ "$i" = 'test-regclient' ]; then
            found=1
        fi
    done
    [ "$found" -eq 1 ]

    run regctl repo ls --limit 4 localhost:${zot_port}
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 4 ]
    [ "${lines[0]}" == "alpine" ]
    [ "${lines[-1]}" == "busybox" ]

    run regctl repo ls --last busybox --limit 1 localhost:${zot_port}
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 1 ]
    [ "${lines[-1]}" == "golang" ]
}

function test_new_list_image_tags_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl tag ls localhost:${zot_port}/test-regclient
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

function test_new_push_manifest_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    manifest=$(regctl manifest get localhost:${zot_port}/test-regclient --format=raw-body)
    run regctl manifest put localhost:${zot_port}/test-regclient:1.0.0 --format oci --content-type application/vnd.oci.image.manifest.v1+json --format oci <<JSON
    $manifest
JSON
    [ "$status" -eq 0 ]
}

function test_new_pull_manifest_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl manifest get localhost:${zot_port}/test-regclient
    [ "$status" -eq 0 ]
}

function test_new_pull_manifest_with_docker_client() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run docker pull localhost:${zot_port}/test-regclient
    [ "$status" -eq 0 ]
}

function test_new_pull_manifest_with_crictl() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run crictl pull localhost:${zot_port}/test-regclient
    [ "$status" -eq 0 ]
}

function test_new_push_oci_artifact_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl artifact put localhost:${zot_port}/artifact:demo <<TXT
this is an artifact
TXT
    [ "$status" -eq 0 ]
}

function test_new_pull_oci_artifact_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl manifest get localhost:${zot_port}/artifact:demo
    [ "$status" -eq 0 ]
    run regctl artifact get localhost:${zot_port}/artifact:demo
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" == "this is an artifact" ]
}

function test_new_push_oci_artifact_references_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl artifact put localhost:${zot_port}/manifest-ref:demo <<TXT
test artifact
TXT
    [ "$status" -eq 0 ]
    run regctl artifact list localhost:${zot_port}/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact put --annotation  demo=true --annotation format=oci --artifact-type "application/vnd.example.icecream.v1" --subject localhost:${zot_port}/manifest-ref:demo << TXT
test reference
TXT
    [ "$status" -eq 0 ]
    # with artifact media-type
    run regctl artifact put localhost:${zot_port}/artifact-ref:demo <<TXT
test artifact
TXT
    [ "$status" -eq 0 ]
    run regctl artifact list localhost:${zot_port}/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact put --annotation  demo=true --annotation format=oci --artifact-type "application/vnd.example.icecream.v1" --subject localhost:${zot_port}/artifact-ref:demo << TXT
test reference
TXT
    [ "$status" -eq 0 ]
}

function test_new_pull_oci_artifact_references_with_regclient() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl artifact list localhost:${zot_port}/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/vnd.example.icecream.v1" localhost:${zot_port}/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/invalid" localhost:${zot_port}/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
    # with artifact media-type
    run regctl artifact list localhost:${zot_port}/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/vnd.example.icecream.v1" localhost:${zot_port}/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 1 ]
    run regctl artifact list --filter-artifact-type "application/invalid" localhost:${zot_port}/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
}

function test_new_push_docker_image() {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    cat > Dockerfile <<DOCKERFILE
    FROM ghcr.io/project-zot/test-images/busybox-docker:1.37
    RUN echo "hello world" > /testfile
DOCKERFILE
    docker build -f Dockerfile . -t localhost:${zot_port}/test
    run docker push localhost:${zot_port}/test
    [ "$status" -eq 1 ]
    run docker pull localhost:${zot_port}/test
    [ "$status" -eq 1 ]
}
