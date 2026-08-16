# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_events
load ../port_helper

function verify_prerequisites() {
    if ! command -v curl >/dev/null 2>&1; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if ! command -v jq >/dev/null 2>&1; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    if ! command -v docker >/dev/null 2>&1; then
        echo "you need to install docker as a prerequisite to running the tests" >&3
        return 1
    fi
}

function setup_file() {
    # Use unique config name based on test file name and test run to avoid conflicts
    export REGISTRY_NAME=$(basename "${BASH_SOURCE[0]}" .bats)-$(basename "${BATS_FILE_TMPDIR}")

    # verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi

    # Setup http server
    http_server_port=$(get_free_port_for_service "http")
    http_event_dir="${BATS_FILE_TMPDIR}/http_events"
    http_server_start http_receiver_scan "${http_server_port}" "${http_event_dir}"
    echo ${http_server_port} > ${BATS_FILE_TMPDIR}/http_server.port
    wait_for_http_server $http_server_port http_receiver_scan

    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20

    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    mkdir -p ${zot_root_dir}
    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    # readTimeout/writeTimeout must exceed how long a cold trivy scan of golang:1.20 can take
    # (observed 83s in CI vs. the 60s Go http.Server default): if the server's WriteTimeout
    # fires while the CVEListForImage handler is still mid-scan, Go's http.Transport silently
    # retries the (idempotent) GET on the client side, and the abandoned first handler keeps
    # running to completion regardless, so both it and the retry publish an ImageScanned event
    # for the same scan, causing an intermittent duplicate.
    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}",
        "readTimeout": "5m",
        "writeTimeout": "5m"
    },
    "log": {
        "level": "debug",
        "output": "${BATS_FILE_TMPDIR}/zot.log"
    },
    "extensions": {
        "search": {
            "enable": true,
            "cve": {
                "updateInterval": "24h"
            }
        },
        "events": {
            "enable": true,
            "sinks": [{
                "type": "http",
                "address": "http://127.0.0.1:${http_server_port}/events",
                "timeout": "15s",
                "credentials": {
                    "username": "jane.joe",
                    "password": "opensesame"
                }
            }]
        }
    }
}
EOF
    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}

    # setup zli to add zot registry to configs
    local registry_url="http://127.0.0.1:${zot_port}/"
    zli_add_config ${REGISTRY_NAME} ${registry_url}
}

function teardown_file() {
    zot_stop_all
    http_server_stop http_receiver_scan
    zli_delete_config ${REGISTRY_NAME}
}

# Waits for at least $expected_count event files, then keeps polling until the
# count holds steady for $settle_seconds before returning - a slow/retried PUT
# can occasionally duplicate a push event (same class of bug as the
# writeTimeout comment in setup_file documents for the CVE-scan side), so
# settling here avoids treating that duplicate as a hard failure while still
# catching a straggler before the caller moves on (e.g. resets the counter).
function wait_for_event_count() {
    local output_path="$1"
    local expected_count="$2"
    local timeout_seconds="${3:-30}"
    local settle_seconds="${4:-3}"
    local elapsed=0
    local count=0
    local last_count=-1
    local stable_for=0

    while [ "$elapsed" -lt "$timeout_seconds" ]; do
        count=$(find "${output_path}" -type f | wc -l)

        if [ "$count" -ge "$expected_count" ]; then
            if [ "$count" -eq "$last_count" ]; then
                stable_for=$((stable_for + 1))
                if [ "$stable_for" -ge "$settle_seconds" ]; then
                    return 0
                fi
            else
                stable_for=0
            fi
        fi

        last_count=$count
        sleep 1
        elapsed=$((elapsed + 1))
    done

    echo "timed out waiting for ${expected_count} events, found ${count}" >&3

    return 1
}

@test "http/publish image scanned event" {
    http_server_port=$(cat ${BATS_FILE_TMPDIR}/http_server.port)
    zot_port=$(cat ${BATS_FILE_TMPDIR}/zot.port)
    output_path=${BATS_FILE_TMPDIR}/http_events

    # Push a new image tag
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.20 \
        docker://127.0.0.1:${zot_port}/golang:1.20
    [ "$status" -eq 0 ]

    sleep 10     # wait a little to populate metadb

    # Event delivery is asynchronous (fired from a goroutine per publish), so wait for the
    # push-triggered events (RepositoryCreated + ImageUpdated, this being a new repo's first
    # push) to actually arrive and settle before resetting, or a late arrival could be
    # miscounted as the scan-triggered event below. Tolerates >2 (a slow/retried PUT can
    # duplicate one of these) since only the scan-triggered count below is under test here.
    wait_for_event_count "${output_path}" 2

    # Reset the event counter so only the scan-triggered event is counted
    run curl -XGET http://127.0.0.1:${http_server_port}/reset
    [ "$status" -eq 0 ]
    [ -d "${output_path}" ] && rm -f "${output_path}"/*.json

    # Triggers a CVE scan synchronously, which should publish an image scanned event
    run ${ZLI_PATH} cve list golang:1.20 --config ${REGISTRY_NAME}
    [ "$status" -eq 0 ]

    # Check the correct number of events were generated
    wait_for_event_count "${output_path}" 1
    count=$(find "${output_path}" -type f | wc -l)
    [ "$count" -eq 1 ]

    # Validate the event
    result=$(jq '.' ${output_path}/1.json)
    [ $(echo "${result}" | jq -r '.headers["Ce-Type"]') = "zotregistry.image.scanned" ]
    [ $(echo "${result}" | jq -r '.body.name') = "golang" ]
    [ $(echo "${result}" | jq -r '.body.reference') = "1.20" ]
    [ $(echo "${result}" | jq -r '.body.digest') != "" ]
    [ $(echo "${result}" | jq -r '.body.digest') != "null" ]
    [ $(echo "${result}" | jq -r '.body.summary.count') != "null" ]
    [ $(echo "${result}" | jq -r '.body.summary.maxSeverity') != "null" ]
}
