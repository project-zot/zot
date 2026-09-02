# Helpers for blob mount authorization blackbox tests (curl + regctl).

load helpers_pushpull_authn

MOUNT_USER1=mountuser1
MOUNT_PASS1=mountSecret1
MOUNT_USER2=mountuser2
MOUNT_PASS2=mountSecret2
MOUNT_REPO1="${MOUNT_USER1}/myrepo"
MOUNT_REPO2="${MOUNT_USER2}/myrepo"
MOUNT_REPO2_OTHER="${MOUNT_USER2}/otherrepo"
MOUNT_REPO1_SECOND="${MOUNT_USER1}/mysecondrepo"
MOUNT_REPO1_CURL="${MOUNT_USER1}/curldestrepo"
MOUNT_REPO1_NOHYDRATE_HEAD="${MOUNT_USER1}/nohydratehead"
MOUNT_REPO1_NOHYDRATE_RANGE="${MOUNT_USER1}/nohydraterange"
MOUNT_REPO1_HYDRATE_HEAD="${MOUNT_USER1}/hydratehead"
MOUNT_REPO1_HYDRATE_RANGE="${MOUNT_USER1}/hydraterange"
MOUNT_REPO2_HYDRATE_HEAD="${MOUNT_USER2}/hydratehead"
MOUNT_REPO2_HYDRATE_RANGE="${MOUNT_USER2}/hydraterange"

function mount_write_htpasswd_file() {
    local htpasswd_file=${1}

    htpasswd -Bbn "${MOUNT_USER1}" "${MOUNT_PASS1}" >>"${htpasswd_file}"
    htpasswd -Bbn "${MOUNT_USER2}" "${MOUNT_PASS2}" >>"${htpasswd_file}"
}

# Args: config, root, port, htpasswd, log, hydrateBlobOnRead (true|false, default false)
function mount_write_zot_config() {
    local zot_config_file=${1}
    local zot_root_dir=${2}
    local zot_port=${3}
    local zot_htpasswd_file=${4}
    local log_file=${5}
    local hydrate_blob_on_read=${6:-false}

    cat >"${zot_config_file}" <<EOF
{
  "distSpecVersion":"1.1.1",
  "storage":{
    "dedupe": true,
    "gc": false,
    "hydrateBlobOnRead": ${hydrate_blob_on_read},
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
        "${MOUNT_USER1}/**": {
          "policies": [
            {
              "users": ["${MOUNT_USER1}"],
              "actions": ["read", "create"]
            }
          ]
        },
        "${MOUNT_USER2}/**": {
          "policies": [
            {
              "users": ["${MOUNT_USER2}"],
              "actions": ["read", "create"]
            }
          ]
        }
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

# Args: $1 = hydrateBlobOnRead (true|false, default false)
function mount_setup_file() {
    local hydrate_blob_on_read=${1:-false}

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
    : >"${zot_htpasswd_file}"
    mount_write_htpasswd_file "${zot_htpasswd_file}"

    echo "${zot_root_dir}" >&3
    mkdir -p "${zot_root_dir}"
    touch "${log_file}"

    mount_write_zot_config "${zot_config_file}" "${zot_root_dir}" "${zot_port}" \
        "${zot_htpasswd_file}" "${log_file}" "${hydrate_blob_on_read}"

    zot_serve "${ZOT_PATH}" "${zot_config_file}"
    wait_zot_reachable "${zot_port}"

    local regctl="${ROOT_DIR}/hack/tools/bin/regctl"
    local -a regctl_host=(--host "reg=localhost:${zot_port},tls=disabled")

    run "${regctl}" "${regctl_host[@]}" registry login \
        "localhost:${zot_port}" -u "${MOUNT_USER1}" -p "${MOUNT_PASS1}"
    [ "${status}" -eq 0 ]
    run "${regctl}" "${regctl_host[@]}" image copy "ocidir://${TEST_DATA_DIR}/busybox:1.36" \
        "localhost:${zot_port}/${MOUNT_REPO1}:1.36"
    [ "${status}" -eq 0 ]

    mount_save_first_layer_digest
}

function mount_teardown() {
    authn_teardown
}

function mount_teardown_file() {
    authn_teardown_file
}

function mount_get_regctl() {
    echo "${ROOT_DIR}/hack/tools/bin/regctl"
}

function mount_regctl_host_flags() {
    echo "--host reg=localhost:$(get_zot_port),tls=disabled"
}

function mount_regctl_login() {
    local user=${1}
    local pass=${2}

    run "$(mount_get_regctl)" $(mount_regctl_host_flags) registry login \
        "localhost:$(get_zot_port)" -u "${user}" -p "${pass}"
    [ "${status}" -eq 0 ]
}

function mount_save_first_layer_digest() {
    local digest_file=${BATS_FILE_TMPDIR}/layer.digest

    run skopeo inspect "oci:${TEST_DATA_DIR}/busybox:1.36"
    [ "${status}" -eq 0 ]

    run jq -r '.Layers[0]' <<<"${output}"
    [ "${status}" -eq 0 ]
    [ -n "${output}" ]

    echo "${output}" >"${digest_file}"
}

function mount_get_layer_digest() {
    cat "${BATS_FILE_TMPDIR}/layer.digest"
}

# Args: $1=user, $2=pass, $3=dest repo, $4=mount digest, $5=optional from repo
# Sets $output to the HTTP status code.
function mount_curl_blob_upload() {
    local user=${1}
    local pass=${2}
    local dest_repo=${3}
    local mount_digest=${4}
    local from_repo=${5:-}
    local zot_port query

    zot_port=$(get_zot_port)
    query="mount=${mount_digest}"
    if [ -n "${from_repo}" ]; then
        query="${query}&from=${from_repo}"
    fi

    run curl -s -o /dev/null -w "%{http_code}" -u "${user}:${pass}" \
        -X POST "http://127.0.0.1:${zot_port}/v2/${dest_repo}/blobs/uploads/?${query}"
}

# Args: $1=user, $2=pass, $3=repo, $4=digest
# Sets $output to the HTTP status code.
function mount_curl_blob_head() {
    local user=${1}
    local pass=${2}
    local repo=${3}
    local digest=${4}
    local zot_port

    zot_port=$(get_zot_port)

    run curl -s -o /dev/null -w "%{http_code}" -u "${user}:${pass}" \
        -I "http://127.0.0.1:${zot_port}/v2/${repo}/blobs/${digest}"
}

# Args: $1=user, $2=pass, $3=repo, $4=digest, $5=optional Range value (default bytes=0-0)
# Sets $output to the HTTP status code.
function mount_curl_blob_range_get() {
    local user=${1}
    local pass=${2}
    local repo=${3}
    local digest=${4}
    local range=${5:-bytes=0-0}
    local zot_port

    zot_port=$(get_zot_port)

    run curl -s -o /dev/null -w "%{http_code}" -u "${user}:${pass}" \
        -H "Range: ${range}" \
        "http://127.0.0.1:${zot_port}/v2/${repo}/blobs/${digest}"
}
