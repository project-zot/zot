load helpers_cloud

function setup() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi

    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local zot_htpasswd_file=${BATS_FILE_TMPDIR}/zot_htpasswd
    htpasswd -Bbn test test123 >> ${zot_htpasswd_file}
    
    echo ${zot_root_dir} >&3

    mkdir -p ${zot_root_dir}

    cat > ${zot_config_file}<<EOF
{
  "distSpecVersion":"1.1.0-dev",
  "storage":{
    "dedupe": true,
    "gc": true,
    "gcDelay": "1h",
    "gcInterval": "6h",
    "rootDirectory": "${zot_root_dir}"
  },
  "http": {
		"address": "127.0.0.1",
		"port": "8080",
    "realm":"zot",
    "auth": {
      "htpasswd": {
        "path": ${zot_htpasswd_file}
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
  }
}
EOF
    zot_serve ${zot_config_file}
    wait_zot_reachable "http://127.0.0.1:8080/v2/_catalog"
}

@test "push image with regclient" {
    run regctl registry set localhost:8080 --tls disabled
    run regctl registry login localhost:8080 -u test -p test123
    [ "$status" -eq 0 ]
    run regctl image copy ocidir://${TEST_DATA_DIR}/golang:1.20 localhost:8080/test-regclient
    [ "$status" -eq 0 ]
}

@test "pull image with regclient" {
    run regctl image copy localhost:8080/test-regclient ocidir://${TEST_DATA_DIR}/golang:1.20
    [ "$status" -eq 0 ]
}
@test "pull image with regclient" {
    run regctl image copy localhost:8080/test-regclient ocidir://${TEST_DATA_DIR}/golang:1.20
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

function teardown() {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    zot_stop
    rm -rf ${zot_root_dir}
}
