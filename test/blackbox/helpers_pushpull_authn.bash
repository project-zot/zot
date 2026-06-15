# Common helper functions for authenticated push/pull blackbox tests.
# Used by pushpull_authn.bats and fips140_authn.bats.

load helpers_pushpull

function verify_authn_prerequisites() {
    if ! verify_prerequisites; then
        return 1
    fi

    if ! command -v htpasswd >/dev/null; then
        echo "you need to install htpasswd as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ "${PUSHPULL_AUTHN_FIPS_MODE:-0}" = 1 ]; then
        if ! command -v mkpasswd >/dev/null; then
            echo "you need to install mkpasswd as a prerequisite to running the tests" >&3
            return 1
        fi
    fi

    return 0
}

function authn_write_htpasswd_file() {
    local htpasswd_file=${1}

    htpasswd -Bbn "${AUTH_USER}" "${AUTH_PASS}" >>"${htpasswd_file}"

    if [ "${PUSHPULL_AUTHN_FIPS_MODE:-0}" = 1 ]; then
        echo "${AUTH_USER2}:$(echo "${AUTH_PASS2}" | mkpasswd -s -R 1 -m sha-256)" >>"${htpasswd_file}"
        echo "${AUTH_USER3}:$(echo "${AUTH_PASS3}" | mkpasswd -s -R 1 -m sha-512)" >>"${htpasswd_file}"
        echo "${AUTH_USER4}:$(echo "${AUTH_PASS4}" | mkpasswd -s -R 0 -m sha-256)" >>"${htpasswd_file}"
        echo "${AUTH_USER5}:$(echo "${AUTH_PASS5}" | mkpasswd -s -R 0 -m sha-512)" >>"${htpasswd_file}"
    fi
}

function authn_write_zot_config() {
    local zot_config_file=${1}
    local zot_root_dir=${2}
    local zot_port=${3}
    local zot_htpasswd_file=${4}
    local log_file=${5}

    cat >"${zot_config_file}" <<EOF
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
    "output": "${log_file}"
  }
}
EOF
}

function authn_setup_file() {
    if ! verify_authn_prerequisites; then
        exit 1
    fi

    pushpull_isolate_regctl_config

    skopeo --insecure-policy copy --format=oci \
        docker://ghcr.io/project-zot/test-images/busybox:1.36 \
        oci:${TEST_DATA_DIR}/busybox:1.36

    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local zot_htpasswd_file=${BATS_FILE_TMPDIR}/zot_htpasswd
    local log_file=${zot_root_dir}/zot-log.json

    zot_port=$(get_free_port_for_service "zot")
    echo "${zot_port}" >"${BATS_FILE_TMPDIR}/zot.port"
    authn_write_htpasswd_file "${zot_htpasswd_file}"

    echo "${zot_root_dir}" >&3
    mkdir -p "${zot_root_dir}"
    touch "${log_file}"

    authn_write_zot_config "${zot_config_file}" "${zot_root_dir}" "${zot_port}" \
        "${zot_htpasswd_file}" "${log_file}"

    if [ "${PUSHPULL_AUTHN_FIPS_MODE:-0}" = 1 ]; then
        export GODEBUG="fips140=only"
    fi

    zot_serve "${ZOT_PATH}" "${zot_config_file}"
    wait_zot_reachable "${zot_port}"

    run regctl registry set "localhost:${zot_port}" --tls disabled
    [ "${status}" -eq 0 ]

    if [ "${PUSHPULL_AUTHN_FIPS_MODE:-0}" = 1 ]; then
        log_output | jq 'contains("fips140 is currently enabled")?' | grep true
    fi
}

function authn_teardown() {
    cat "${BATS_FILE_TMPDIR}/zot/zot-log.json"
}

function authn_teardown_file() {
    zot_stop_all

    if [ "${PUSHPULL_AUTHN_FIPS_MODE:-0}" = 1 ]; then
        unset GODEBUG
    fi
}

function helper_authn_regctl_login() {
    local user=${1}
    local pass=${2}

    run regctl registry login "localhost:$(get_zot_port)" -u "${user}" -p "${pass}"
    [ "${status}" -eq 0 ]
}

# Args: $1 = source reference, $2 = destination repository
function helper_authn_push_image_with_regclient() {
    local source_ref=${1}
    local dest_repo=${2}

    helper_authn_regctl_login "${AUTH_USER}" "${AUTH_PASS}"
    run regctl image copy "${source_ref}" "localhost:$(get_zot_port)/${dest_repo}"
    [ "${status}" -eq 0 ]
}

# Args: $1 = source repository, $2 = destination reference
function helper_authn_pull_image_with_regclient() {
    local source_repo=${1}
    local dest_ref=${2}

    helper_authn_regctl_login "${AUTH_USER}" "${AUTH_PASS}"
    run regctl image copy "localhost:$(get_zot_port)/${source_repo}" "${dest_ref}"
    [ "${status}" -eq 0 ]
}

# Args: $1 = artifact reference
function helper_authn_push_oci_artifact_with_regclient() {
    local ref=${1}

    helper_authn_regctl_login "${AUTH_USER}" "${AUTH_PASS}"
    helper_push_oci_artifact_with_regclient "${ref}"
}

# Args: $1 = artifact reference, $2 = expected artifact content
function helper_authn_pull_oci_artifact_with_regclient() {
    local ref=${1}
    local expected_content=${2}

    helper_authn_regctl_login "${AUTH_USER}" "${AUTH_PASS}"
    helper_pull_oci_artifact_with_regclient "${ref}" "${expected_content}"
}

function helper_authn_push_oci_artifact_references_with_regclient() {
    helper_authn_regctl_login "${AUTH_USER}" "${AUTH_PASS}"
    helper_push_oci_artifact_references_with_regclient 0
}

function helper_authn_list_oci_artifact_references_with_regclient() {
    helper_authn_regctl_login "${AUTH_USER}" "${AUTH_PASS}"
    helper_pull_oci_artifact_references_with_regclient 1
}

# Args: $1=username, $2=password
function helper_authn_ml_artifacts() {
    local user=${1}
    local pass=${2}
    local zot_port sha256_in sha256_out

    helper_authn_regctl_login "${user}" "${pass}"
    zot_port=$(get_zot_port)

    run curl --fail -L -0 \
        https://github.com/tarilabs/demo20231212/raw/main/v1.nb20231206162408/mnist.onnx \
        -o "${BATS_FILE_TMPDIR}/mnist.onnx"
    [ "${status}" -eq 0 ]

    run sha256sum "${BATS_FILE_TMPDIR}/mnist.onnx"
    [ "${status}" -eq 0 ]
    sha256_in=$(echo "${output}" | awk '{print $1}')
    [ -n "${sha256_in}" ]

    run regctl artifact put \
        --annotation description="used for demo purposes" \
        --annotation model_format_name="onnx" \
        --annotation model_format_version="1" \
        --artifact-type "application/vnd.model.type" \
        "localhost:${zot_port}/models/my-model-from-gh:v1" \
        -f "${BATS_FILE_TMPDIR}/mnist.onnx"
    [ "${status}" -eq 0 ]

    run regctl artifact list "localhost:${zot_port}/models/my-model-from-gh:v1" \
        --format '{{jsonPretty .}}'
    [ "${status}" -eq 0 ]

    run regctl artifact list --filter-artifact-type "application/vnd.model.type" \
        "localhost:${zot_port}/models/my-model-from-gh:v1" \
        --format '{{jsonPretty .}}'
    [ "${status}" -eq 0 ]

    run bash -c "regctl artifact get 'localhost:${zot_port}/models/my-model-from-gh:v1' >'${BATS_FILE_TMPDIR}/mnist.onnx.check'"
    [ "${status}" -eq 0 ]

    run sha256sum "${BATS_FILE_TMPDIR}/mnist.onnx.check"
    [ "${status}" -eq 0 ]
    sha256_out=$(echo "${output}" | awk '{print $1}')
    [ -n "${sha256_out}" ]
    [ "${sha256_in}" = "${sha256_out}" ]
}

# Args: $1=username, $2=password, $3=hash_type, $4=should_succeed (true/false)
function helper_authn_verify_auth_and_push() {
    local user=${1}
    local pass=${2}
    local hash_type=${3}
    local should_succeed=${4}

    helper_authn_regctl_login "${user}" "${pass}"
    run regctl image copy "ocidir://${TEST_DATA_DIR}/busybox:1.36" \
        "localhost:$(get_zot_port)/test-${hash_type}"

    if [ "${should_succeed}" = true ]; then
        [ "${status}" -eq 0 ]
    else
        [ "${status}" -eq 1 ]
        log_output | jq 'contains("htpasswd bcrypt failed since fips140 is enabled")?' | grep true
    fi
}

# Args: $1=username, $2=password, $3=source_repo, $4=dest_ref
function helper_authn_pull_image_with_auth() {
    local user=${1}
    local pass=${2}
    local source_repo=${3}
    local dest_ref=${4}

    helper_authn_regctl_login "${user}" "${pass}"
    run regctl image copy "localhost:$(get_zot_port)/${source_repo}" \
        "ocidir://${TEST_DATA_DIR}/busybox:${dest_ref}"
    [ "${status}" -eq 0 ]
}

# Args: $1=username, $2=password, $3=artifact_ref, $4=artifact_body
function helper_authn_push_oci_artifact_with_auth() {
    local user=${1}
    local pass=${2}
    local artifact_ref=${3}
    local artifact_body=${4}

    helper_authn_regctl_login "${user}" "${pass}"
    run regctl artifact put "localhost:$(get_zot_port)/${artifact_ref}" <<TXT
${artifact_body}
TXT
    [ "${status}" -eq 0 ]
}

# Args: $1=username, $2=password, $3=artifact_ref, $4=expected_body
function helper_authn_pull_oci_artifact_with_auth() {
    local user=${1}
    local pass=${2}
    local artifact_ref=${3}
    local expected_body=${4}

    helper_authn_regctl_login "${user}" "${pass}"
    run regctl manifest get "localhost:$(get_zot_port)/${artifact_ref}"
    [ "${status}" -eq 0 ]
    run regctl artifact get "localhost:$(get_zot_port)/${artifact_ref}"
    [ "${status}" -eq 0 ]
    [ "${lines[-1]}" = "${expected_body}" ]
}

function helper_authn_push_oci_artifact_references_with_auth() {
    helper_authn_regctl_login "${AUTH_USER2}" "${AUTH_PASS2}"
    helper_push_oci_artifact_references_with_regclient 0
}

function helper_authn_list_oci_artifact_references_with_auth() {
    helper_authn_regctl_login "${AUTH_USER2}" "${AUTH_PASS2}"
    helper_pull_oci_artifact_references_with_regclient 1
}

function helper_authn_ml_artifacts_with_auth() {
    helper_authn_ml_artifacts "${AUTH_USER3}" "${AUTH_PASS3}"
}
