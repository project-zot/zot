load helpers_zot
load ../port_helper

function verify_prerequisites {
    if ! command -v curl > /dev/null 2>&1; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if ! command -v openssl > /dev/null 2>&1; then
        echo "you need to install openssl as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

# Generate TLS certificates for testing
function generate_certs() {
    local cert_dir=$1
    mkdir -p ${cert_dir}
    
    # Generate CA certificate
    openssl req -newkey rsa:2048 -nodes -days 365 -x509 \
        -keyout ${cert_dir}/ca.key \
        -out ${cert_dir}/ca.crt \
        -subj "/CN=Test CA" 2>/dev/null
    
    # Generate initial server certificate (version 1)
    openssl req -newkey rsa:2048 -nodes \
        -keyout ${cert_dir}/server.key \
        -out ${cert_dir}/server.csr \
        -subj "/OU=TestServer/CN=Server v1" 2>/dev/null
    
    openssl x509 -req -days 365 -sha256 \
        -in ${cert_dir}/server.csr \
        -CA ${cert_dir}/ca.crt \
        -CAkey ${cert_dir}/ca.key \
        -CAcreateserial \
        -out ${cert_dir}/server.cert \
        -extfile <(echo subjectAltName = IP:127.0.0.1) 2>/dev/null
}

# Generate new server certificate with different CN
function regenerate_server_cert() {
    local cert_dir=$1
    local version=$2
    
    # Generate new server certificate (version 2)
    openssl req -newkey rsa:2048 -nodes \
        -keyout ${cert_dir}/server.key \
        -out ${cert_dir}/server.csr \
        -subj "/OU=TestServer/CN=Server v${version}" 2>/dev/null
    
    openssl x509 -req -days 365 -sha256 \
        -in ${cert_dir}/server.csr \
        -CA ${cert_dir}/ca.crt \
        -CAkey ${cert_dir}/ca.key \
        -CAcreateserial \
        -out ${cert_dir}/server.cert \
        -extfile <(echo subjectAltName = IP:127.0.0.1) 2>/dev/null
}

function setup_file() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi

    # Generate certificates
    local cert_dir=${BATS_FILE_TMPDIR}/certs
    generate_certs ${cert_dir}

    # Setup zot server with TLS
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port

    mkdir -p ${zot_root_dir}

    cat > ${zot_config_file}<<EOF
{
  "distSpecVersion":"1.1.1",
  "storage":{
    "rootDirectory": "${zot_root_dir}"
  },
  "http": {
    "address": "127.0.0.1",
    "port": "${zot_port}",
    "tls": {
      "cert": "${cert_dir}/server.cert",
      "key": "${cert_dir}/server.key"
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
    # conditionally printing on failure is possible from teardown but not from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot.log
}

function teardown_file() {
    zot_stop_all
}

@test "verify initial TLS connection works" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    cert_dir=${BATS_FILE_TMPDIR}/certs
    
    # Test HTTPS connection with CA certificate
    run curl --cacert ${cert_dir}/ca.crt https://127.0.0.1:${zot_port}/v2/
    [ "$status" -eq 0 ]
}

@test "verify certificate details - initial cert" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    cert_dir=${BATS_FILE_TMPDIR}/certs
    
    # Get certificate subject from server
    cert_subject=$(echo | openssl s_client -connect 127.0.0.1:${zot_port} -showcerts 2>/dev/null | \
        openssl x509 -noout -subject 2>/dev/null | grep "Server v1")
    
    # Verify we got the initial certificate (v1)
    [ ! -z "$cert_subject" ]
}

@test "reload certificate and verify new cert is used" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    cert_dir=${BATS_FILE_TMPDIR}/certs
    
    # Verify initial connection works
    run curl --cacert ${cert_dir}/ca.crt https://127.0.0.1:${zot_port}/v2/
    [ "$status" -eq 0 ]
    
    # Wait a moment to ensure modification time will be different
    sleep 2
    
    # Generate new certificate with different CommonName
    regenerate_server_cert ${cert_dir} 2
    
    # Wait for certificate to be detected and reloaded
    sleep 2
    
    # Verify connection still works with new certificate
    run curl --cacert ${cert_dir}/ca.crt https://127.0.0.1:${zot_port}/v2/
    [ "$status" -eq 0 ]
    
    # Get certificate subject from server
    cert_subject=$(echo | openssl s_client -connect 127.0.0.1:${zot_port} -showcerts 2>/dev/null | \
        openssl x509 -noout -subject 2>/dev/null | grep "Server v2")
    
    # Verify we got the new certificate (v2)
    [ ! -z "$cert_subject" ]
}

@test "verify multiple certificate reloads work" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    cert_dir=${BATS_FILE_TMPDIR}/certs
    
    for i in 3 4 5; do
        # Generate new certificate
        regenerate_server_cert ${cert_dir} ${i}
        
        # Wait for reload
        sleep 2
        
        # Verify connection works
        run curl --cacert ${cert_dir}/ca.crt https://127.0.0.1:${zot_port}/v2/
        [ "$status" -eq 0 ]
        
        # Verify new certificate is in use
        cert_subject=$(echo | openssl s_client -connect 127.0.0.1:${zot_port} -showcerts 2>/dev/null | \
            openssl x509 -noout -subject 2>/dev/null | grep "Server v${i}")
        [ ! -z "$cert_subject" ]
    done
}

@test "verify server continues working if certificate reload fails" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    cert_dir=${BATS_FILE_TMPDIR}/certs
    
    # Get current certificate version
    cert_subject_before=$(echo | openssl s_client -connect 127.0.0.1:${zot_port} -showcerts 2>/dev/null | \
        openssl x509 -noout -subject 2>/dev/null)
    
    # Temporarily remove certificate files (will cause reload to fail)
    # Note: Moving the file won't trigger fsnotify (only Write/Create events are monitored),
    # so this test relies on the maybeReload() fallback mechanism being triggered during
    # the TLS handshake when curl connects below. This verifies the server continues
    # serving with the old certificate when reload fails.
    mv ${cert_dir}/server.cert ${cert_dir}/server.cert.backup
    
    # Wait and try to connect - should still work with old certificate
    # The maybeReload() mechanism will detect the missing file but won't fail the handshake
    sleep 2
    run curl --cacert ${cert_dir}/ca.crt https://127.0.0.1:${zot_port}/v2/
    [ "$status" -eq 0 ]
    
    # Restore certificate
    mv ${cert_dir}/server.cert.backup ${cert_dir}/server.cert
    
    # Verify still using old certificate
    cert_subject_after=$(echo | openssl s_client -connect 127.0.0.1:${zot_port} -showcerts 2>/dev/null | \
        openssl x509 -noout -subject 2>/dev/null)
    [ "$cert_subject_before" = "$cert_subject_after" ]
}
