# Common helper functions and test utilities for blackbox push/pull-style tests.
# Used by pushpull.bats, fips140.bats, and upgrade BATS suites.

function verify_prerequisites() {
    if ! command -v curl >/dev/null; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if ! command -v jq >/dev/null; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function get_zot_port() {
    cat "${BATS_FILE_TMPDIR}/zot.port"
}

function helper_assert_output_contains_line() {
    local expected=${1}
    local found=0
    local line

    for line in "${lines[@]}"; do
        if [ "${line}" = "${expected}" ]; then
            found=1
            break
        fi
    done

    [ "${found}" -eq 1 ]
}

function helper_assert_line_specs() {
    local spec index expected

    for spec in "$@"; do
        index=${spec%%:*}
        expected=${spec#*:}
        [ "${lines[${index}]}" = "${expected}" ]
    done
}

function helper_assert_catalog_has_repo() {
    local repository=${1}
    local zot_port
    zot_port=$(get_zot_port)

    run curl "http://127.0.0.1:${zot_port}/v2/_catalog"
    [ "${status}" -eq 0 ]
    [ "$(echo "${lines[-1]}" | jq --arg name "${repository}" 'any(.repositories[]; . == $name)')" = true ]
}

function helper_assert_repo_has_tag() {
    local repository=${1}
    local tag=${2}
    local zot_port
    zot_port=$(get_zot_port)

    run curl "http://127.0.0.1:${zot_port}/v2/${repository}/tags/list"
    [ "${status}" -eq 0 ]
    [ "$(echo "${lines[-1]}" | jq --arg tag "${tag}" 'any(.tags[]; . == $tag)')" = true ]
}

function helper_assert_oci_index_has_ref_name() {
    local index_file=${1}
    local tag=${2}

    run jq -e --arg tag "${tag}" 'any(.manifests[]; .annotations."org.opencontainers.image.ref.name" == $tag)' "${index_file}"
    [ "${status}" -eq 0 ]
    [ "${lines[-1]}" = true ]
}

# Args: $1 = image_name, $2 = tag, $3 = source reference (optional)
function helper_push_image() {
    local image_name=${1:-golang}
    local tag=${2:-1.20}
    local source_ref=${3:-oci:${TEST_DATA_DIR}/${image_name}:${tag}}
    local zot_port
    zot_port=$(get_zot_port)

    run skopeo --insecure-policy copy --dest-tls-verify=false \
        "${source_ref}" \
        "docker://127.0.0.1:${zot_port}/${image_name}:${tag}"
    [ "${status}" -eq 0 ]

    helper_assert_catalog_has_repo "${image_name}"
    helper_assert_repo_has_tag "${image_name}" "${tag}"
}

# Args: $1 = image_name, $2 = tag
function helper_pull_image() {
    local image_name=${1:-golang}
    local tag=${2:-1.20}
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    local zot_port
    zot_port=$(get_zot_port)

    run skopeo --insecure-policy copy --src-tls-verify=false \
        "docker://127.0.0.1:${zot_port}/${image_name}:${tag}" \
        "oci:${oci_data_dir}/${image_name}:${tag}"
    [ "${status}" -eq 0 ]

    helper_assert_oci_index_has_ref_name "${oci_data_dir}/${image_name}/index.json" "${tag}"
}

# Args: $1 = source_image, $2 = destination image name, $3 = tag
function helper_push_image_index() {
    local source_image=${1:-docker://public.ecr.aws/docker/library/busybox:latest}
    local dest_name=${2:-busybox}
    local tag=${3:-latest}
    local zot_port
    zot_port=$(get_zot_port)

    run skopeo --insecure-policy copy --format=oci --dest-tls-verify=false --multi-arch=all \
        "${source_image}" \
        "docker://127.0.0.1:${zot_port}/${dest_name}:${tag}"
    [ "${status}" -eq 0 ]

    helper_assert_catalog_has_repo "${dest_name}"
    helper_assert_repo_has_tag "${dest_name}" "${tag}"
}

# Args: $1 = image_name, $2 = tag
function helper_pull_image_index() {
    local image_name=${1:-busybox}
    local tag=${2:-latest}
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    local zot_port
    zot_port=$(get_zot_port)

    run skopeo --insecure-policy copy --src-tls-verify=false --multi-arch=all \
        "docker://127.0.0.1:${zot_port}/${image_name}:${tag}" \
        "oci:${oci_data_dir}/${image_name}:${tag}"
    [ "${status}" -eq 0 ]
    helper_assert_oci_index_has_ref_name "${oci_data_dir}/${image_name}/index.json" "${tag}"

    run skopeo --insecure-policy --override-arch=arm64 --override-os=linux copy --src-tls-verify=false --multi-arch=all \
        "docker://127.0.0.1:${zot_port}/${image_name}:${tag}" \
        "oci:${oci_data_dir}/${image_name}:${tag}"
    [ "${status}" -eq 0 ]
    helper_assert_oci_index_has_ref_name "${oci_data_dir}/${image_name}/index.json" "${tag}"
}

# Args: $1 = image_name, $2 = tag
function helper_pull_image_index_and_delete() {
    local image_name=${1:-busybox}
    local tag=${2:-latest}
    local zot_port
    zot_port=$(get_zot_port)

    helper_pull_image_index "${image_name}" "${tag}"

    run curl -X DELETE "http://127.0.0.1:${zot_port}/v2/${image_name}/manifests/${tag}"
    [ "${status}" -eq 0 ]
}

# Args: $1 = artifact_name, $2 = tag
function helper_push_oras_artifact() {
    local artifact_name=${1:-hello-artifact}
    local tag=${2:-v2}
    local zot_port
    zot_port=$(get_zot_port)

    echo '{"name":"foo","value":"bar"}' > config.json
    echo "hello world" > artifact.txt
    run oras push --plain-http "127.0.0.1:${zot_port}/${artifact_name}:${tag}" \
        --config config.json:application/vnd.acme.rocket.config.v1+json artifact.txt:text/plain -d -v
    [ "${status}" -eq 0 ]
    rm -f artifact.txt config.json
}

# Args: $1 = artifact_name, $2 = tag
function helper_pull_oras_artifact() {
    local artifact_name=${1:-hello-artifact}
    local tag=${2:-v2}
    local zot_port
    zot_port=$(get_zot_port)

    run oras pull --plain-http "127.0.0.1:${zot_port}/${artifact_name}:${tag}" -d -v
    [ "${status}" -eq 0 ]
    grep -q "hello world" artifact.txt
    rm -f artifact.txt
}

# Args: $1 = image_name, $2 = tag
function helper_attach_oras_artifacts() {
    local image_name=${1:-golang}
    local tag=${2:-1.20}
    local zot_port
    zot_port=$(get_zot_port)

    echo '{"artifact": "", "signature": "pat hancock"}' > "${BATS_FILE_TMPDIR}/signature.json"
    run oras attach --disable-path-validation --plain-http "127.0.0.1:${zot_port}/${image_name}:${tag}" \
        --artifact-type 'signature/example' "${BATS_FILE_TMPDIR}/signature.json:application/json"
    [ "${status}" -eq 0 ]

    echo "{\"version\": \"0.0.0.0\", \"artifact\": \"'127.0.0.1:${zot_port}/${image_name}:${tag}'\", \"contents\": \"good\"}" > "${BATS_FILE_TMPDIR}/sbom.json"
    run oras attach --disable-path-validation --plain-http "127.0.0.1:${zot_port}/${image_name}:${tag}" \
        --artifact-type 'sbom/example' "${BATS_FILE_TMPDIR}/sbom.json:application/json"
    [ "${status}" -eq 0 ]
}

# Args: $1 = image_name, $2 = tag, $3 = expected artifact count
function helper_discover_oras_artifacts() {
    local image_name=${1:-golang}
    local tag=${2:-1.20}
    local expected_count=${3:-2}
    local zot_port
    zot_port=$(get_zot_port)

    run oras discover --plain-http --format json "127.0.0.1:${zot_port}/${image_name}:${tag}"
    [ "${status}" -eq 0 ]
    [ "$(echo "${output}" | jq -r '.manifests | length')" -eq "${expected_count}" ]
}

function helper_add_and_list_tags_using_oras() {
    local zot_port
    zot_port=$(get_zot_port)

    run skopeo --insecure-policy copy --dest-tls-verify=false \
        "oci:${TEST_DATA_DIR}/golang:1.20" \
        "docker://127.0.0.1:${zot_port}/oras-tags:1.20"
    [ "${status}" -eq 0 ]

    run oras tag --plain-http "127.0.0.1:${zot_port}/oras-tags:1.20" 1 new latest
    [ "${status}" -eq 0 ]

    run oras repo tags --plain-http "127.0.0.1:${zot_port}/oras-tags"
    [ "${status}" -eq 0 ]
    echo "${output}"
    [ "$(echo "${output}" | wc -l)" -eq 4 ]
    [ "${lines[-1]}" = "new" ]
    [ "${lines[-2]}" = "latest" ]
    [ "${lines[-3]}" = "1.20" ]
    [ "${lines[-4]}" = "1" ]

    run oras repo tags --plain-http --last new "127.0.0.1:${zot_port}/oras-tags"
    [ "${status}" -eq 0 ]
    echo "${output}"
    [ -z "${output}" ]

    run oras repo tags --plain-http --last latest "127.0.0.1:${zot_port}/oras-tags"
    [ "${status}" -eq 0 ]
    echo "${output}"
    [ "$(echo "${output}" | wc -l)" -eq 1 ]
    [ "${lines[-1]}" = "new" ]

    run oras repo tags --plain-http --last "1.20" "127.0.0.1:${zot_port}/oras-tags"
    [ "${status}" -eq 0 ]
    echo "${output}"
    [ "$(echo "${output}" | wc -l)" -eq 2 ]
    [ "${lines[-2]}" = "latest" ]
    [ "${lines[-1]}" = "new" ]

    run oras repo tags --plain-http --last "1" "127.0.0.1:${zot_port}/oras-tags"
    [ "${status}" -eq 0 ]
    echo "${output}"
    [ "$(echo "${output}" | wc -l)" -eq 3 ]
    [ "${lines[-3]}" = "1.20" ]
    [ "${lines[-2]}" = "latest" ]
    [ "${lines[-1]}" = "new" ]
}

function helper_push_helm_chart() {
    local zot_port chart_version
    zot_port=$(get_zot_port)

    run helm package "${BATS_FILE_TMPDIR}/helm-charts/charts/zot" -d "${BATS_FILE_TMPDIR}"
    [ "${status}" -eq 0 ]

    chart_version=$(awk '/version/{printf $2}' "${BATS_FILE_TMPDIR}/helm-charts/charts/zot/Chart.yaml")
    run helm push "${BATS_FILE_TMPDIR}/zot-${chart_version}.tgz" "oci://localhost:${zot_port}/zot-chart"
    [ "${status}" -eq 0 ]
}

function helper_pull_helm_chart() {
    local zot_port chart_version
    zot_port=$(get_zot_port)
    chart_version=$(awk '/version/{printf $2}' "${BATS_FILE_TMPDIR}/helm-charts/charts/zot/Chart.yaml")

    run helm pull "oci://localhost:${zot_port}/zot-chart/zot" --version "${chart_version}" -d "${BATS_FILE_TMPDIR}"
    [ "${status}" -eq 0 ]
}

function helper_push_image_with_regclient() {
    local zot_port
    zot_port=$(get_zot_port)

    run regctl registry set "localhost:${zot_port}" --tls disabled
    [ "${status}" -eq 0 ]
    run regctl image copy "ocidir://${TEST_DATA_DIR}/golang:1.20" "localhost:${zot_port}/test-regclient"
    [ "${status}" -eq 0 ]
}

function helper_pull_image_with_regclient() {
    local zot_port
    zot_port=$(get_zot_port)

    run regctl image copy "localhost:${zot_port}/test-regclient" "ocidir://${TEST_DATA_DIR}/golang:1.20"
    [ "${status}" -eq 0 ]
}

# Args: $1 = page limit, $2 = --last cursor repo, $3 = expected next repo,
#       $@ = optional index:repo assertions against the limited result page.
function helper_list_repositories_with_regclient_pagination() {
    local limit=${1:-2}
    local cursor_repo=${2:-busybox}
    local expected_next_repo=${3:-golang}
    local zot_port
    zot_port=$(get_zot_port)
    shift 3 || true

    run regctl repo ls "localhost:${zot_port}"
    [ "${status}" -eq 0 ]
    helper_assert_output_contains_line test-regclient

    run regctl repo ls --limit "${limit}" "localhost:${zot_port}"
    [ "${status}" -eq 0 ]
    echo "${output}"
    [ "$(echo "${output}" | wc -l)" -eq "${limit}" ]
    helper_assert_line_specs "$@"

    run regctl repo ls --last "${cursor_repo}" --limit 1 "localhost:${zot_port}"
    [ "${status}" -eq 0 ]
    echo "${output}"
    [ "$(echo "${output}" | wc -l)" -eq 1 ]
    [ "${lines[-1]}" = "${expected_next_repo}" ]
}

function helper_list_image_tags_with_regclient() {
    local zot_port
    zot_port=$(get_zot_port)

    run regctl tag ls "localhost:${zot_port}/test-regclient"
    [ "${status}" -eq 0 ]
    helper_assert_output_contains_line latest
}

function helper_push_manifest_with_regclient() {
    local zot_port manifest
    zot_port=$(get_zot_port)
    manifest=$(regctl manifest get "localhost:${zot_port}/test-regclient" --format=raw-body)

    run regctl manifest put "localhost:${zot_port}/test-regclient:1.0.0" \
        --format oci \
        --content-type application/vnd.oci.image.manifest.v1+json \
        --format oci <<JSON
${manifest}
JSON
    [ "${status}" -eq 0 ]
}

function helper_pull_manifest_with_regclient() {
    local zot_port
    zot_port=$(get_zot_port)

    run regctl manifest get "localhost:${zot_port}/test-regclient"
    [ "${status}" -eq 0 ]
}

function helper_pull_manifest_with_docker_client() {
    local zot_port
    zot_port=$(get_zot_port)

    run docker pull "localhost:${zot_port}/test-regclient"
    [ "${status}" -eq 0 ]
}

function helper_pull_manifest_with_crictl() {
    local zot_port
    zot_port=$(get_zot_port)

    run crictl pull "localhost:${zot_port}/test-regclient"
    [ "${status}" -eq 0 ]
}

function helper_push_oci_artifact_with_regclient() {
    local zot_port
    zot_port=$(get_zot_port)

    run regctl artifact put "localhost:${zot_port}/artifact:demo" <<TXT
this is an artifact
TXT
    [ "${status}" -eq 0 ]
}

function helper_pull_oci_artifact_with_regclient() {
    local zot_port
    zot_port=$(get_zot_port)

    run regctl manifest get "localhost:${zot_port}/artifact:demo"
    [ "${status}" -eq 0 ]
    run regctl artifact get "localhost:${zot_port}/artifact:demo"
    [ "${status}" -eq 0 ]
    [ "${lines[-1]}" = "this is an artifact" ]
}

# Args: $1 = expected initial referrers count
function helper_push_oci_artifact_references_with_regclient() {
    local expected_initial_count=${1:-0}
    local zot_port
    zot_port=$(get_zot_port)

    run regctl artifact put "localhost:${zot_port}/manifest-ref:demo" <<TXT
test artifact
TXT
    [ "${status}" -eq 0 ]
    run regctl artifact list "localhost:${zot_port}/manifest-ref:demo" --format raw-body
    [ "${status}" -eq 0 ]
    [ "$(echo "${lines[-1]}" | jq '.manifests | length')" -eq "${expected_initial_count}" ]

    run regctl artifact put --annotation demo=true --annotation format=oci \
        --artifact-type "application/vnd.example.icecream.v1" \
        --subject "localhost:${zot_port}/manifest-ref:demo" <<TXT
test reference
TXT
    [ "${status}" -eq 0 ]

    run regctl artifact put "localhost:${zot_port}/artifact-ref:demo" <<TXT
test artifact
TXT
    [ "${status}" -eq 0 ]
    run regctl artifact list "localhost:${zot_port}/artifact-ref:demo" --format raw-body
    [ "${status}" -eq 0 ]
    [ "$(echo "${lines[-1]}" | jq '.manifests | length')" -eq "${expected_initial_count}" ]

    run regctl artifact put --annotation demo=true --annotation format=oci \
        --artifact-type "application/vnd.example.icecream.v1" \
        --subject "localhost:${zot_port}/artifact-ref:demo" <<TXT
test reference
TXT
    [ "${status}" -eq 0 ]
}

# Args: $1 = expected referrers count
function helper_pull_oci_artifact_references_with_regclient() {
    local expected_count=${1:-1}
    local zot_port
    zot_port=$(get_zot_port)

    run regctl artifact list "localhost:${zot_port}/manifest-ref:demo" --format raw-body
    [ "${status}" -eq 0 ]
    [ "$(echo "${lines[-1]}" | jq '.manifests | length')" -eq "${expected_count}" ]
    run regctl artifact list --filter-artifact-type "application/vnd.example.icecream.v1" "localhost:${zot_port}/manifest-ref:demo" --format raw-body
    [ "${status}" -eq 0 ]
    [ "$(echo "${lines[-1]}" | jq '.manifests | length')" -eq "${expected_count}" ]
    run regctl artifact list --filter-artifact-type "application/invalid" "localhost:${zot_port}/manifest-ref:demo" --format raw-body
    [ "${status}" -eq 0 ]
    [ "$(echo "${lines[-1]}" | jq '.manifests | length')" -eq 0 ]

    run regctl artifact list "localhost:${zot_port}/artifact-ref:demo" --format raw-body
    [ "${status}" -eq 0 ]
    [ "$(echo "${lines[-1]}" | jq '.manifests | length')" -eq "${expected_count}" ]
    run regctl artifact list --filter-artifact-type "application/vnd.example.icecream.v1" "localhost:${zot_port}/artifact-ref:demo" --format raw-body
    [ "${status}" -eq 0 ]
    [ "$(echo "${lines[-1]}" | jq '.manifests | length')" -eq "${expected_count}" ]
    run regctl artifact list --filter-artifact-type "application/invalid" "localhost:${zot_port}/artifact-ref:demo" --format raw-body
    [ "${status}" -eq 0 ]
    [ "$(echo "${lines[-1]}" | jq '.manifests | length')" -eq 0 ]
}

function helper_push_docker_image() {
    local zot_port
    zot_port=$(get_zot_port)

    cat > Dockerfile <<DOCKERFILE
FROM ghcr.io/project-zot/test-images/busybox-docker:1.37
RUN echo "hello world" > /testfile
DOCKERFILE
    run sh -c "unset GODEBUG; docker build -f Dockerfile -t localhost:${zot_port}/test ."
    [ "${status}" -eq 0 ]
    run docker push "localhost:${zot_port}/test"
    [ "${status}" -eq 1 ]
    run docker pull "localhost:${zot_port}/test"
    [ "${status}" -eq 1 ]
}
