# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()
#
# ModelPack (https://modelpack.org) packages AI models as OCI artifacts: an image manifest whose
# artifactType and config name a model, with one layer per model file. modctl is its reference
# client. Its v0.2.2 release still writes the earlier application/vnd.cnai.model.* media types,
# while the spec now names them application/vnd.cncf.model.*, so the spec form is pushed with
# oras as well.

load helpers_zot
load ../port_helper

MODEL_REPO=models/tiny
MODEL_TAG=v1
SPEC_MODEL_REPO=models/tiny-spec

function verify_prerequisites() {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v jq) ]; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v modctl) ]; then
        echo "you need to install modctl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v oras) ]; then
        echo "you need to install oras as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

# modctl keeps built and pulled models in a local store; each use gets its own.
function modctl_with_store() {
    local store=${1}
    shift
    modctl --storage-dir ${BATS_FILE_TMPDIR}/${store} --log-dir ${BATS_FILE_TMPDIR}/modctl-logs --no-progress "$@"
}

function setup_file() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi

    # A small model with one file of each ModelPack kind: weight config, weight, code and doc.
    local model_dir=${BATS_FILE_TMPDIR}/model
    mkdir -p ${model_dir}
    echo '{"architectures":["TinyModel"],"model_type":"tiny","torch_dtype":"float16"}' > ${model_dir}/config.json
    echo '{"version":"1.0"}' > ${model_dir}/tokenizer.json
    head -c 1048576 /dev/urandom > ${model_dir}/model.safetensors
    echo 'print("tiny model")' > ${model_dir}/infer.py
    echo '# Tiny model' > ${model_dir}/README.md
    echo 'Apache-2.0' > ${model_dir}/LICENSE

    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local zot_log_file=${BATS_FILE_TMPDIR}/zot.log
    mkdir -p ${zot_root_dir}
    echo ${zot_log_file} > ${BATS_FILE_TMPDIR}/zot.logpath

    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    cat > ${zot_config_file}<<EOF
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
        "output": "${zot_log_file}"
    },
    "extensions": {
        "search": {
            "enable": true
        }
    }
}
EOF
    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}
}

# Print zot logs only when a test fails (see dump_zot_logs_on_failure).
function teardown() {
    dump_zot_logs_on_failure "$(cat ${BATS_FILE_TMPDIR}/zot.logpath)"
}

function teardown_file() {
    zot_stop_all
}

@test "build and push a model with modctl" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    local model_dir=${BATS_FILE_TMPDIR}/model

    run modctl_with_store build-store modelfile generate --name tiny-model --arch transformer --family tiny \
        --format safetensors --precision fp16 --param-size 1m --output ${BATS_FILE_TMPDIR} ${model_dir}
    [ "$status" -eq 0 ]

    cd ${model_dir}
    run modctl_with_store build-store build -f ${BATS_FILE_TMPDIR}/Modelfile \
        -t 127.0.0.1:${zot_port}/${MODEL_REPO}:${MODEL_TAG} .
    [ "$status" -eq 0 ]

    run modctl_with_store build-store push --plain-http 127.0.0.1:${zot_port}/${MODEL_REPO}:${MODEL_TAG}
    [ "$status" -eq 0 ]

    run curl -s http://127.0.0.1:${zot_port}/v2/${MODEL_REPO}/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${output}" | jq -r '.tags[]') = "${MODEL_TAG}" ]
}

@test "model manifest keeps its ModelPack artifact, config and layer types" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`

    run curl -s -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        http://127.0.0.1:${zot_port}/v2/${MODEL_REPO}/manifests/${MODEL_TAG}
    [ "$status" -eq 0 ]
    local manifest="${output}"

    [ $(echo "${manifest}" | jq -r '.artifactType') = "application/vnd.cnai.model.manifest.v1+json" ]
    [ $(echo "${manifest}" | jq -r '.config.mediaType') = "application/vnd.cnai.model.config.v1+json" ]
    [ $(echo "${manifest}" | jq '.layers | length') -eq 6 ]

    local layer_type
    for layer_type in weight.config weight code doc; do
        echo "${manifest}" | jq -e --arg t "application/vnd.cnai.model.${layer_type}.v1.raw" \
            'any(.layers[]; .mediaType == $t)'
    done

    # each layer names the model file it holds
    [ $(echo "${manifest}" | jq -r '.layers[] | select(.mediaType == "application/vnd.cnai.model.weight.v1.raw") |
        .annotations["org.cnai.model.filepath"]') = "model.safetensors" ]

    # the config blob describes the model
    local config_digest=$(echo "${manifest}" | jq -r '.config.digest')
    run curl -s http://127.0.0.1:${zot_port}/v2/${MODEL_REPO}/blobs/${config_digest}
    [ "$status" -eq 0 ]
    [ $(echo "${output}" | jq -r '.descriptor.name') = "tiny-model" ]
    [ $(echo "${output}" | jq -r '.config.format') = "safetensors" ]
    [ $(echo "${output}" | jq '.modelfs.diffIds | length') -eq 6 ]
}

@test "pull and extract a model with modctl" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    local extract_dir=${BATS_FILE_TMPDIR}/extracted

    run modctl_with_store pull-store pull --plain-http 127.0.0.1:${zot_port}/${MODEL_REPO}:${MODEL_TAG}
    [ "$status" -eq 0 ]

    run modctl_with_store pull-store extract --output ${extract_dir} 127.0.0.1:${zot_port}/${MODEL_REPO}:${MODEL_TAG}
    [ "$status" -eq 0 ]

    run diff -r ${BATS_FILE_TMPDIR}/model ${extract_dir}
    [ "$status" -eq 0 ]
}

@test "fetch selected model files with modctl" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    local fetch_dir=${BATS_FILE_TMPDIR}/fetched

    run modctl_with_store fetch-store fetch --plain-http --output ${fetch_dir} --patterns '*.json' \
        127.0.0.1:${zot_port}/${MODEL_REPO}:${MODEL_TAG}
    [ "$status" -eq 0 ]

    # only the matching layers are downloaded
    [ "$(ls ${fetch_dir} | sort | xargs)" = "config.json tokenizer.json" ]
    run diff ${BATS_FILE_TMPDIR}/model/config.json ${fetch_dir}/config.json
    [ "$status" -eq 0 ]
}

@test "inspect a model in zot with modctl" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`

    run modctl_with_store inspect-store inspect --remote --plain-http 127.0.0.1:${zot_port}/${MODEL_REPO}:${MODEL_TAG}
    [ "$status" -eq 0 ]
    [ $(echo "${output}" | jq -r '.Name') = "tiny-model" ]
    [ $(echo "${output}" | jq -r '.Format') = "safetensors" ]
    [ $(echo "${output}" | jq '.Layers | length') -eq 6 ]
}

@test "search lists a model with its artifact type" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`

    run curl -s -X POST -H "Content-Type: application/json" http://127.0.0.1:${zot_port}/v2/_zot/ext/search \
        --data '{ "query": "{ ImageList(repo: \"'${MODEL_REPO}'\") { Results { RepoName Tag ArtifactType Manifests { Layers { Size } } } } }" }'
    [ "$status" -eq 0 ]
    [ $(echo "${output}" | jq -r '.data.ImageList.Results[0].Tag') = "${MODEL_TAG}" ]
    [ $(echo "${output}" | jq -r '.data.ImageList.Results[0].ArtifactType') = "application/vnd.cnai.model.manifest.v1+json" ]
    [ $(echo "${output}" | jq '.data.ImageList.Results[0].Manifests[0].Layers | length') -eq 6 ]
}

@test "attach an SBOM to a model and find it through referrers" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    local sbom_dir=${BATS_FILE_TMPDIR}/sbom
    mkdir -p ${sbom_dir}
    echo '{"spdxVersion":"SPDX-2.3","name":"tiny-model"}' > ${sbom_dir}/sbom.spdx.json

    cd ${sbom_dir}
    run oras attach --plain-http --artifact-type application/spdx+json \
        127.0.0.1:${zot_port}/${MODEL_REPO}:${MODEL_TAG} sbom.spdx.json:application/spdx+json
    [ "$status" -eq 0 ]

    local model_digest=$(oras resolve --plain-http 127.0.0.1:${zot_port}/${MODEL_REPO}:${MODEL_TAG})
    run curl -s "http://127.0.0.1:${zot_port}/v2/${MODEL_REPO}/referrers/${model_digest}?artifactType=application/spdx%2Bjson"
    [ "$status" -eq 0 ]
    [ $(echo "${output}" | jq '.manifests | length') -eq 1 ]
    [ $(echo "${output}" | jq -r '.manifests[0].artifactType') = "application/spdx+json" ]
}

@test "push and pull a model with the ModelPack spec media types" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    local push_dir=${BATS_FILE_TMPDIR}/spec-push
    local pull_dir=${BATS_FILE_TMPDIR}/spec-pull
    mkdir -p ${push_dir} ${pull_dir}
    cp ${BATS_FILE_TMPDIR}/model/{config.json,model.safetensors,README.md} ${push_dir}

    # raw layers are stored uncompressed, so each diffId is the digest of the file, in push order
    local diff_ids=""
    local file
    for file in config.json model.safetensors README.md; do
        diff_ids="${diff_ids:+${diff_ids},}\"sha256:$(sha256sum ${push_dir}/${file} | awk '{print $1}')\""
    done
    cat > ${push_dir}/model-config.json<<EOF
{"descriptor":{"name":"tiny-model","family":"tiny"},"config":{"architecture":"transformer","format":"safetensors"},"modelfs":{"type":"layers","diffIds":[${diff_ids}]}}
EOF
    cat > ${BATS_FILE_TMPDIR}/spec-annotations.json<<EOF
{
    "config.json": {"org.cncf.model.filepath": "config.json"},
    "model.safetensors": {"org.cncf.model.filepath": "model.safetensors"},
    "README.md": {"org.cncf.model.filepath": "README.md"}
}
EOF

    cd ${push_dir}
    run oras push --plain-http --artifact-type application/vnd.cncf.model.manifest.v1+json \
        --config model-config.json:application/vnd.cncf.model.config.v1+json \
        --annotation-file ${BATS_FILE_TMPDIR}/spec-annotations.json \
        127.0.0.1:${zot_port}/${SPEC_MODEL_REPO}:${MODEL_TAG} \
        config.json:application/vnd.cncf.model.weight.config.v1.raw \
        model.safetensors:application/vnd.cncf.model.weight.v1.raw \
        README.md:application/vnd.cncf.model.doc.v1.raw
    [ "$status" -eq 0 ]

    run curl -s -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        http://127.0.0.1:${zot_port}/v2/${SPEC_MODEL_REPO}/manifests/${MODEL_TAG}
    [ "$status" -eq 0 ]
    [ $(echo "${output}" | jq -r '.artifactType') = "application/vnd.cncf.model.manifest.v1+json" ]
    [ $(echo "${output}" | jq -r '.config.mediaType') = "application/vnd.cncf.model.config.v1+json" ]
    [ $(echo "${output}" | jq -r '.layers[] | select(.mediaType == "application/vnd.cncf.model.weight.v1.raw") |
        .annotations["org.cncf.model.filepath"]') = "model.safetensors" ]

    # the config lists the layers' content digests in manifest order
    local layer_digests=$(echo "${output}" | jq -c '[.layers[].digest]')
    local config_digest=$(echo "${output}" | jq -r '.config.digest')
    run curl -s http://127.0.0.1:${zot_port}/v2/${SPEC_MODEL_REPO}/blobs/${config_digest}
    [ "$status" -eq 0 ]
    [ "$(echo "${output}" | jq -c '.modelfs.diffIds')" = "${layer_digests}" ]

    cd ${pull_dir}
    run oras pull --plain-http 127.0.0.1:${zot_port}/${SPEC_MODEL_REPO}:${MODEL_TAG}
    [ "$status" -eq 0 ]
    local file
    for file in config.json model.safetensors README.md; do
        run diff ${push_dir}/${file} ${pull_dir}/${file}
        [ "$status" -eq 0 ]
    done
}

@test "delete a model" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`

    local model_digest=$(oras resolve --plain-http 127.0.0.1:${zot_port}/${MODEL_REPO}:${MODEL_TAG})
    run curl -s -o /dev/null -w "%{http_code}" -X DELETE \
        http://127.0.0.1:${zot_port}/v2/${MODEL_REPO}/manifests/${model_digest}
    [ "$status" -eq 0 ]
    [ "${output}" = "202" ]

    run curl -s -o /dev/null -w "%{http_code}" -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        http://127.0.0.1:${zot_port}/v2/${MODEL_REPO}/manifests/${MODEL_TAG}
    [ "$status" -eq 0 ]
    [ "${output}" = "404" ]
}
