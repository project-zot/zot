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

    if [ ! $(command -v htpasswd) ]; then
        echo "you need to install htpasswd as a prerequisite to running the tests" >&3
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
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/test-images/busybox:1.36 oci:${TEST_DATA_DIR}/busybox:1.36

    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local zot_htpasswd_file=${BATS_FILE_TMPDIR}/zot_htpasswd
    zot_port=$(get_free_port)
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    htpasswd -Bbn ${AUTH_USER} ${AUTH_PASS} >> ${zot_htpasswd_file}

    echo ${zot_root_dir} >&3

    mkdir -p ${zot_root_dir}

    cat > ${zot_config_file}<<EOF
{
  "distSpecVersion":"1.1.0",
  "storage":{
    "dedupe": true,
    "gc": true,
    "gcDelay": "1h",
    "gcInterval": "6h",
    "rootDirectory": "${zot_root_dir}"
  },
  "http": {
		"address": "127.0.0.1",
		"port": "${zot_port}",
    "realm":"zot",
    "auth": {
      "htpasswd": {
        "path": "${zot_htpasswd_file}"
      },
      "failDelay": 5
    },
    "accessControl": {
      "repositories": {
        "**": {
          "anonymousPolicy": ["read"],
          "defaultPolicy": ["read", "create"]
        }
      },
      "adminPolicy": {
        "users": ["admin"],
        "actions": ["read", "create", "update", "delete"]
      }
    }
  },
  "log":{
    "level":"debug",
    "output": "${BATS_FILE_TMPDIR}/zot.log"
  }
}
EOF
    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}
}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot.log
}

function teardown_file() {
    zot_stop_all
}

@test "push image with regclient" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    run regctl registry login localhost:${zot_port} -u ${AUTH_USER} -p ${AUTH_PASS}
    [ "$status" -eq 0 ]
    run regctl image copy ocidir://${TEST_DATA_DIR}/busybox:1.36 localhost:${zot_port}/test-regclient
    [ "$status" -eq 0 ]
}

@test "pull image with regclient" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl image copy localhost:${zot_port}/test-regclient ocidir://${TEST_DATA_DIR}/busybox:latest
    [ "$status" -eq 0 ]
}

@test "push OCI artifact with regclient" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl artifact put localhost:${zot_port}/artifact:demo <<EOF
this is an artifact
EOF
    [ "$status" -eq 0 ]
}

@test "pull OCI artifact with regclient" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl manifest get localhost:${zot_port}/artifact:demo
    [ "$status" -eq 0 ]
    run regctl artifact get localhost:${zot_port}/artifact:demo
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" == "this is an artifact" ]
}

@test "push OCI artifact references with regclient" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl artifact put localhost:${zot_port}/manifest-ref:demo <<EOF
test artifact
EOF
    [ "$status" -eq 0 ]
    run regctl artifact list localhost:${zot_port}/manifest-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
    run regctl artifact put --annotation  demo=true --annotation format=oci --artifact-type "application/vnd.example.icecream.v1" --subject localhost:${zot_port}/manifest-ref:demo << EOF
test reference
EOF
    [ "$status" -eq 0 ]
    # with artifact media-type
    run regctl artifact put localhost:${zot_port}/artifact-ref:demo <<EOF
test artifact
EOF
    [ "$status" -eq 0 ]
    run regctl artifact list localhost:${zot_port}/artifact-ref:demo --format raw-body
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests | length') -eq 0 ]
    run regctl artifact put --annotation  demo=true --annotation format=oci --artifact-type "application/vnd.example.icecream.v1" --subject localhost:${zot_port}/artifact-ref:demo << EOF
test reference
EOF
    [ "$status" -eq 0 ]
}

@test "list OCI artifact references with regclient" {
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

@test "ML artifacts" {
  # download model data
  curl -v -L0 https://github.com/tarilabs/demo20231212/raw/main/v1.nb20231206162408/mnist.onnx -o ${BATS_FILE_TMPDIR}/mnist.onnx
  sha256_in=$(sha256sum ${BATS_FILE_TMPDIR}/mnist.onnx | awk '{print $1}')

  zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`

  # upload artifact with required annotations and version
  regctl artifact put --annotation description="used for demo purposes" --annotation model_format_name="onnx" --annotation model_format_version="1" --artifact-type "application/vnd.model.type" localhost:${zot_port}/models/my-model-from-gh:v1 -f ${BATS_FILE_TMPDIR}/mnist.onnx

  # list artifacts
  regctl artifact list localhost:${zot_port}/models/my-model-from-gh:v1 --format '{{jsonPretty .}}'

  # list artifacts of type
  regctl artifact list --filter-artifact-type "application/vnd.model.type" localhost:${zot_port}/models/my-model-from-gh:v1 --format '{{jsonPretty .}}'

  # get artifact
  regctl artifact get localhost:${zot_port}/models/my-model-from-gh:v1 > ${BATS_FILE_TMPDIR}/mnist.onnx.check
  sha256_out=$(sha256sum ${BATS_FILE_TMPDIR}/mnist.onnx.check | awk '{print $1}')
  [ "$sha256_in" = "$sha256_out" ]
}
