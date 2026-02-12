# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load ../port_helper

function verify_prerequisites {
    if ! command -v curl >/dev/null 2>&1; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if ! command -v jq >/dev/null 2>&1; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    if ! command -v openssl >/dev/null 2>&1; then
        echo "you need to install openssl as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

# Generate a self-signed certificate with the given CN
function generate_self_signed_cert() {
    local cert_path=${1}
    local key_path=${2}
    local common_name=${3:-"localhost"}
    local days=${4:-365}

    openssl req -x509 -newkey rsa:2048 -keyout "${key_path}" -out "${cert_path}" \
        -days ${days} -nodes \
        -subj "/C=US/ST=Test/L=Test/O=Zot/CN=${common_name}"
}

# Wait for a condition to be true, polling up to max_attempts times with interval_seconds between attempts
# Usage: wait_for_condition <max_attempts> <interval_seconds> "<command>"
# Returns 0 on success, 1 on timeout
function wait_for_condition() {
    local max_attempts=${1}
    local interval=${2}
    local condition_cmd=${3}
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if eval "${condition_cmd}"; then
            echo "Condition met after $attempt attempts" >&3
            return 0
        fi
        
        if [ $attempt -lt $max_attempts ]; then
            sleep "${interval}"
        fi
        
        ((attempt++))
    done
    
    echo "Condition timed out after $max_attempts attempts" >&3
    return 1
}

function setup_file() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/test-images/busybox:1.36 oci:${TEST_DATA_DIR}/busybox:1.36

    # Setup zot server with TLS
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local zot_cert_file=${BATS_FILE_TMPDIR}/server.cert
    local zot_key_file=${BATS_FILE_TMPDIR}/server.key
    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port

    mkdir -p ${zot_root_dir}

    # Generate initial TLS certificate
    generate_self_signed_cert "${zot_cert_file}" "${zot_key_file}" "127.0.0.1" 365

    # Create zot config with TLS enabled
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
    "tls": {
      "cert": "${zot_cert_file}",
      "key": "${zot_key_file}"
    }
  },
  "log":{
    "level":"debug",
    "output": "${BATS_FILE_TMPDIR}/zot.log"
  }
}
EOF

    echo ${zot_root_dir} >&3
    zot_serve ${ZOT_PATH} ${zot_config_file}
    
    # Wait for server to be ready by polling for connectivity
    wait_for_condition 30 0.2 "curl -k --max-time 5 --connect-timeout 3 https://127.0.0.1:${zot_port}/v2/_catalog >/dev/null 2>&1"
}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot.log 2>/dev/null || true
}

function teardown_file() {
    zot_stop_all
}

@test "TLS connection succeeds with self-signed certificate" {
    zot_port=$(cat ${BATS_FILE_TMPDIR}/zot.port)
    
    # Test with curl using insecure flag since we're using self-signed cert
    run curl -k --max-time 5 --connect-timeout 3 https://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
}

@test "push image with TLS enabled" {
    zot_port=$(cat ${BATS_FILE_TMPDIR}/zot.port)
    
    # Use skopeo to push image over HTTPS with insecure TLS verification
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/busybox:1.36 \
        docker://127.0.0.1:${zot_port}/busybox:1.36
    [ "$status" -eq 0 ]
}

@test "pull image with TLS enabled" {
    zot_port=$(cat ${BATS_FILE_TMPDIR}/zot.port)
    local temp_oci_dir=${BATS_FILE_TMPDIR}/busybox-pulled
    
    mkdir -p ${temp_oci_dir}
    
    # Pull the pushed image back
    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:${zot_port}/busybox:1.36 \
        oci:${temp_oci_dir}
    [ "$status" -eq 0 ]
    
    # Verify OCI image was downloaded
    [ -f "${temp_oci_dir}/oci-layout" ]
}

@test "dynamic certificate reload: verify server uses new certificate after update" {
    zot_port=$(cat ${BATS_FILE_TMPDIR}/zot.port)
    local zot_cert_file=${BATS_FILE_TMPDIR}/server.cert
    local zot_key_file=${BATS_FILE_TMPDIR}/server.key
    
    # Get the certificate fingerprint before update
    cert_fingerprint_before=$(openssl x509 -fingerprint -sha256 -noout -in "${zot_cert_file}" 2>/dev/null | cut -d'=' -f2)
    server_fingerprint_before=$(openssl s_client -connect 127.0.0.1:${zot_port} -servername 127.0.0.1 -showcerts </dev/null 2>/dev/null \
        | openssl x509 -fingerprint -sha256 -noout 2>/dev/null | cut -d'=' -f2)
    [ -n "${server_fingerprint_before}" ]
    
    # Keep fetching catalog to ensure server is responsive before cert update
    wait_for_condition 10 0.5 "curl -k --max-time 5 --connect-timeout 3 https://127.0.0.1:${zot_port}/v2/_catalog >/dev/null 2>&1"
    
    # Update the certificate with a new one
    # This simulates a real-world scenario where certificates are renewed
    generate_self_signed_cert "${zot_cert_file}" "${zot_key_file}" "127.0.0.1" 365
    
    # Wait for file system changes to be visible and stat cache to expire
    # (allows time for inotify to detect changes or stat-based check to trigger)
    wait_for_condition 10 0.1 "[ \"$(openssl x509 -fingerprint -sha256 -noout -in \"${zot_cert_file}\" 2>/dev/null | cut -d'=' -f2)\" != \"${cert_fingerprint_before}\" ]"
    
    # Request a new fingerprint after expecting the server to reload
    wait_for_condition 20 0.2 "[ \"$(openssl s_client -connect 127.0.0.1:${zot_port} -servername 127.0.0.1 -showcerts </dev/null 2>/dev/null | openssl x509 -fingerprint -sha256 -noout 2>/dev/null | cut -d'=' -f2)\" != \"${server_fingerprint_before}\" ]" || true
    
    # Make several requests to ensure server picks up the new certificate
    # The server should automatically reload it through the GetCertificate callback
    server_fingerprint_after=""
    for i in {1..10}; do
        server_fingerprint_after=$(openssl s_client -connect 127.0.0.1:${zot_port} -servername 127.0.0.1 -showcerts </dev/null 2>/dev/null \
            | openssl x509 -fingerprint -sha256 -noout 2>/dev/null | cut -d'=' -f2)
        run curl -k --max-time 5 --connect-timeout 3 https://127.0.0.1:${zot_port}/v2/_catalog
        if [ "$status" -eq 0 ] && [ -n "${server_fingerprint_after}" ] && \
            [ "${server_fingerprint_before}" != "${server_fingerprint_after}" ]; then
            # Server is using the new certificate
            echo "Request $i succeeded with new certificate" >&3
            break
        fi
        if [ $i -lt 10 ]; then
            sleep 0.2
        fi
    done
    
    [ -n "${server_fingerprint_after}" ]
    [ "${server_fingerprint_before}" != "${server_fingerprint_after}" ]
    [ "$status" -eq 0 ]
}

@test "TLS works with multiple concurrent connections after certificate reload" {
    zot_port=$(cat ${BATS_FILE_TMPDIR}/zot.port)
    local zot_cert_file=${BATS_FILE_TMPDIR}/server.cert
    local zot_key_file=${BATS_FILE_TMPDIR}/server.key
    
    # Regenerate certificate to trigger reload
    generate_self_signed_cert "${zot_cert_file}" "${zot_key_file}" "127.0.0.1" 365
    
    # Wait for certificate to be reloaded by making requests
    wait_for_condition 20 0.2 "curl -k --max-time 5 --connect-timeout 3 https://127.0.0.1:${zot_port}/v2/_catalog >/dev/null 2>&1"
    
    # Test multiple concurrent requests
    local failed=0
    local pids=()
    for i in {1..5}; do
        (curl -k --max-time 5 --connect-timeout 3 https://127.0.0.1:${zot_port}/v2/_catalog > /dev/null 2>&1) &
        pids+=($!)
    done
    
    # Wait for all background requests to complete
    for pid in "${pids[@]}"; do
        if ! wait "$pid"; then
            failed=$((failed + 1))
        fi
    done
    [ "$failed" -eq 0 ]
    
    # If any failed, the test will fail
    # Check that at least one request succeeds by making one more
    run curl -k --max-time 5 --connect-timeout 3 https://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
}

@test "certificate reload doesn't require server restart" {
    zot_port=$(cat ${BATS_FILE_TMPDIR}/zot.port)
    local zot_cert_file=${BATS_FILE_TMPDIR}/server.cert
    local zot_key_file=${BATS_FILE_TMPDIR}/server.key
    
    # Get initial server PID
    local zot_pid=$(cat ${BATS_FILE_TMPDIR}/zot.pid | awk '{print $1}')
    
    # Make a request to establish the server is running
    run curl -k --max-time 5 --connect-timeout 3 https://127.0.0.1:${zot_port}/v2/_catalog
    [ "$status" -eq 0 ]
    
    # Verify server is still running with same PID
    kill -0 ${zot_pid} 2>/dev/null
    [ "$?" -eq 0 ]
    
    # Update certificate multiple times
    for iteration in {1..3}; do
        generate_self_signed_cert "${zot_cert_file}" "${zot_key_file}" "127.0.0.1" 365
        
        # Wait for server to reload the new certificate
        wait_for_condition 20 0.2 "curl -k --max-time 5 --connect-timeout 3 https://127.0.0.1:${zot_port}/v2/_catalog >/dev/null 2>&1" || true
        
        # Server should still be running with the same PID
        kill -0 ${zot_pid} 2>/dev/null
        [ "$?" -eq 0 ]
        
        # Requests should still work
        run curl -k --max-time 5 --connect-timeout 3 https://127.0.0.1:${zot_port}/v2/_catalog
        [ "$status" -eq 0 ]
    done
}
