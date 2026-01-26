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

    if [ ! $(command -v htpasswd) ]; then
        echo "you need to install htpasswd as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v mkpasswd) ]; then
        echo "you need to install mkpasswd as a prerequisite to running the tests" >&3
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
    ZOT_LOG_FILE=${zot_root_dir}/zot-log.json
    local zot_htpasswd_file=${BATS_FILE_TMPDIR}/zot_htpasswd
    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    htpasswd -Bbn ${AUTH_USER} ${AUTH_PASS} >> ${zot_htpasswd_file} # bcrypt
    echo "${AUTH_USER2}:$(echo ${AUTH_PASS2} | mkpasswd -s -R 1 -m sha-256)" >> ${zot_htpasswd_file} # sha256
    echo "${AUTH_USER3}:$(echo ${AUTH_PASS3} | mkpasswd -s -R 1 -m sha-512)" >> ${zot_htpasswd_file} # sha512
    echo "${AUTH_USER4}:$(echo ${AUTH_PASS4} | mkpasswd -s -R 0 -m sha-256)" >> ${zot_htpasswd_file} # sha256 zero rounds
    echo "${AUTH_USER5}:$(echo ${AUTH_PASS5} | mkpasswd -s -R 0 -m sha-512)" >> ${zot_htpasswd_file} # sha512 zero rounds

    echo ${zot_root_dir} >&3

    mkdir -p ${zot_root_dir}

    touch ${ZOT_LOG_FILE}
    cat > ${zot_config_file}<<EOF
{
  "distSpecVersion":"1.1.1",
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
    "output": "${ZOT_LOG_FILE}"
  }
}
EOF
    export GODEBUG="fips140=only"
    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}
    log_output | jq 'contains("fips140 is currently enabled")' | grep true
}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot/zot-log.json
    
    # Logout from registry if zot_port exists
    if [ -f ${BATS_FILE_TMPDIR}/zot.port ]; then
        zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
        regctl registry logout localhost:${zot_port} 2>/dev/null || true
    fi
}

function teardown_file() {
    zot_stop_all
    unset GODEBUG
}

# Helper function to verify authentication and image push
# Args: $1=username, $2=password, $3=hash_type, $4=should_succeed (true/false)
function verify_auth_and_push() {
    local user="$1"
    local pass="$2"
    local hash_type="$3"
    local should_succeed="$4"
    
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
   
    # Disable TLS for regctl to avoid X25519 issues when regctl runs in FIPS mode
    # This must be done before regctl registry login, as login automatically pings the registry
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]

    # anonymous authn is set for zot, so all auth is ignored for the /v2/ ping
    run regctl registry login localhost:${zot_port} -u ${user} -p ${pass}
    [ "$status" -eq 0 ]
    
    run regctl image copy ocidir://${TEST_DATA_DIR}/busybox:1.36 localhost:${zot_port}/test-${hash_type}
    
    if [ "$should_succeed" = "true" ]; then
        [ "$status" -eq 0 ]
    else
        [ "$status" -eq 1 ]
        log_output | jq 'contains("htpasswd bcrypt failed since fips140 is enabled")' | grep true
    fi
}

@test "push image with regclient - setup registry" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
}

@test "push image with bcrypt auth (should fail in FIPS mode)" {
    verify_auth_and_push "${AUTH_USER}" "${AUTH_PASS}" "bcrypt" "false"
}

@test "push image with SHA256 auth (should succeed)" {
    verify_auth_and_push "${AUTH_USER2}" "${AUTH_PASS2}" "sha256" "true"
}

@test "push image with SHA512 auth (should succeed)" {
    verify_auth_and_push "${AUTH_USER3}" "${AUTH_PASS3}" "sha512" "true"
}

@test "push image with SHA256 auth with 0 rounds (should succeed)" {
    verify_auth_and_push "${AUTH_USER4}" "${AUTH_PASS4}" "sha256-0rounds" "true"
}

@test "push image with SHA512 auth with 0 rounds (should succeed)" {
    verify_auth_and_push "${AUTH_USER5}" "${AUTH_PASS5}" "sha512-0rounds" "true"
}

@test "pull image with SHA256 auth" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    run regctl registry login localhost:${zot_port} -u ${AUTH_USER2} -p ${AUTH_PASS2}
    [ "$status" -eq 0 ]
    run regctl image copy localhost:${zot_port}/test-sha256 ocidir://${TEST_DATA_DIR}/busybox:sha256-pulled
    [ "$status" -eq 0 ]
}

@test "pull image with SHA512 auth" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    run regctl registry login localhost:${zot_port} -u ${AUTH_USER3} -p ${AUTH_PASS3}
    [ "$status" -eq 0 ]
    run regctl image copy localhost:${zot_port}/test-sha512 ocidir://${TEST_DATA_DIR}/busybox:sha512-pulled
    [ "$status" -eq 0 ]
}

@test "pull image with SHA256 auth with 0 rounds" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    run regctl registry login localhost:${zot_port} -u ${AUTH_USER4} -p ${AUTH_PASS4}
    [ "$status" -eq 0 ]
    run regctl image copy localhost:${zot_port}/test-sha256-0rounds ocidir://${TEST_DATA_DIR}/busybox:sha256-0rounds-pulled
    [ "$status" -eq 0 ]
}

@test "pull image with SHA512 auth with 0 rounds" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    run regctl registry login localhost:${zot_port} -u ${AUTH_USER5} -p ${AUTH_PASS5}
    [ "$status" -eq 0 ]
    run regctl image copy localhost:${zot_port}/test-sha512-0rounds ocidir://${TEST_DATA_DIR}/busybox:sha512-0rounds-pulled
    [ "$status" -eq 0 ]
}

@test "push OCI artifact with SHA256 auth" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    run regctl registry login localhost:${zot_port} -u ${AUTH_USER2} -p ${AUTH_PASS2}
    [ "$status" -eq 0 ]
    run regctl artifact put localhost:${zot_port}/artifact-sha256:demo <<EOF
this is an artifact with SHA256
EOF
    [ "$status" -eq 0 ]
}

@test "push OCI artifact with SHA512 auth" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    run regctl registry login localhost:${zot_port} -u ${AUTH_USER3} -p ${AUTH_PASS3}
    [ "$status" -eq 0 ]
    run regctl artifact put localhost:${zot_port}/artifact-sha512:demo <<EOF
this is an artifact with SHA512
EOF
    [ "$status" -eq 0 ]
}

@test "push OCI artifact with SHA256 auth with 0 rounds" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    run regctl registry login localhost:${zot_port} -u ${AUTH_USER4} -p ${AUTH_PASS4}
    [ "$status" -eq 0 ]
    run regctl artifact put localhost:${zot_port}/artifact-sha256-0rounds:demo <<EOF
this is an artifact with SHA256 and 0 rounds
EOF
    [ "$status" -eq 0 ]
}

@test "push OCI artifact with SHA512 auth with 0 rounds" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    run regctl registry login localhost:${zot_port} -u ${AUTH_USER5} -p ${AUTH_PASS5}
    [ "$status" -eq 0 ]
    run regctl artifact put localhost:${zot_port}/artifact-sha512-0rounds:demo <<EOF
this is an artifact with SHA512 and 0 rounds
EOF
    [ "$status" -eq 0 ]
}

@test "pull OCI artifact with SHA256 auth" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    run regctl registry login localhost:${zot_port} -u ${AUTH_USER2} -p ${AUTH_PASS2}
    [ "$status" -eq 0 ]
    run regctl manifest get localhost:${zot_port}/artifact-sha256:demo
    [ "$status" -eq 0 ]
    run regctl artifact get localhost:${zot_port}/artifact-sha256:demo
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" == "this is an artifact with SHA256" ]
}

@test "pull OCI artifact with SHA512 auth" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    run regctl registry login localhost:${zot_port} -u ${AUTH_USER3} -p ${AUTH_PASS3}
    [ "$status" -eq 0 ]
    run regctl manifest get localhost:${zot_port}/artifact-sha512:demo
    [ "$status" -eq 0 ]
    run regctl artifact get localhost:${zot_port}/artifact-sha512:demo
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" == "this is an artifact with SHA512" ]
}

@test "pull OCI artifact with SHA256 auth with 0 rounds" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    run regctl registry login localhost:${zot_port} -u ${AUTH_USER4} -p ${AUTH_PASS4}
    [ "$status" -eq 0 ]
    run regctl manifest get localhost:${zot_port}/artifact-sha256-0rounds:demo
    [ "$status" -eq 0 ]
    run regctl artifact get localhost:${zot_port}/artifact-sha256-0rounds:demo
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" == "this is an artifact with SHA256 and 0 rounds" ]
}

@test "pull OCI artifact with SHA512 auth with 0 rounds" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    run regctl registry login localhost:${zot_port} -u ${AUTH_USER5} -p ${AUTH_PASS5}
    [ "$status" -eq 0 ]
    run regctl manifest get localhost:${zot_port}/artifact-sha512-0rounds:demo
    [ "$status" -eq 0 ]
    run regctl artifact get localhost:${zot_port}/artifact-sha512-0rounds:demo
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" == "this is an artifact with SHA512 and 0 rounds" ]
}

@test "push OCI artifact references with regclient" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    run regctl registry login localhost:${zot_port} -u ${AUTH_USER2} -p ${AUTH_PASS2}
    [ "$status" -eq 0 ]
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
    run regctl registry set localhost:${zot_port} --tls disabled
    [ "$status" -eq 0 ]
    run regctl registry login localhost:${zot_port} -u ${AUTH_USER2} -p ${AUTH_PASS2}
    [ "$status" -eq 0 ]
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
  zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
  run regctl registry set localhost:${zot_port} --tls disabled
  [ "$status" -eq 0 ]
  # Use SHA512 auth for ML artifacts test
  run regctl registry login localhost:${zot_port} -u ${AUTH_USER3} -p ${AUTH_PASS3}
  [ "$status" -eq 0 ]
  
  # download model data
  curl -v -L0 https://github.com/tarilabs/demo20231212/raw/main/v1.nb20231206162408/mnist.onnx -o ${BATS_FILE_TMPDIR}/mnist.onnx
  sha256_in=$(sha256sum ${BATS_FILE_TMPDIR}/mnist.onnx | awk '{print $1}')

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
