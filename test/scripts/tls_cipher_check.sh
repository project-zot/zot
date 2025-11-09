#!/usr/bin/env bash

# Script to check TLS cipher suites used in FIPS vs non-FIPS mode
# Usage: ./tls_cipher_check.sh [fips|non-fips] [host:port]

set -e

MODE="${1:-non-fips}"
HOST="${2:-localhost:8080}"

# FIPS-compliant cipher suites (TLS 1.2)
# See https://cs.opensource.google/go/go/+/refs/tags/go1.24.9:src/crypto/tls/defaults.go;l=123
FIPS_TLS12_CIPHERS=(
    "ECDHE-ECDSA-AES128-GCM-SHA256"
    "ECDHE-ECDSA-AES256-GCM-SHA384"
    "ECDHE-RSA-AES128-GCM-SHA256"
    "ECDHE-RSA-AES256-GCM-SHA384"
)

# FIPS-compliant cipher suites (TLS 1.3)
# See https://cs.opensource.google/go/go/+/refs/tags/go1.24.9:src/crypto/tls/defaults.go;l=131
FIPS_TLS13_CIPHERS=(
    "TLS_AES_128_GCM_SHA256"
    "TLS_AES_256_GCM_SHA384"
)

# Non-FIPS cipher suites (TLS 1.2)
NON_FIPS_TLS12_CIPHERS=(
    "ECDHE-ECDSA-CHACHA20-POLY1305"
    "ECDHE-RSA-CHACHA20-POLY1305"
)

# Non-FIPS cipher suites (TLS 1.3)
NON_FIPS_TLS13_CIPHERS=(
    "TLS_CHACHA20_POLY1305_SHA256"
)

echo "=== TLS Cipher Suite Check (Mode: $MODE) ==="
echo "Testing connection to: $HOST"
echo ""

# Test a specific cipher suite
# Returns 0 if connection succeeds, 1 if it fails
test_cipher() {
    local tls_version=$1
    local cipher=$2
    local output

    # -no_ticket disables TLS session tickets to ensure each connection performs
    # a full handshake, providing consistent and accurate cipher suite detection
    if [[ "$tls_version" == "1.2" ]]; then
        output=$(echo | openssl s_client -connect "$HOST" -tls1_2 -cipher "$cipher" -no_ticket 2>&1 || true)
    elif [[ "$tls_version" == "1.3" ]]; then
        output=$(echo | openssl s_client -connect "$HOST" -tls1_3 -ciphersuites "$cipher" -no_ticket 2>&1 || true)
    else
        echo "Unknown TLS version: $tls_version"
        return 1
    fi

    # Output openssl output for debugging
    echo "Debug: Testing TLS $tls_version cipher '$cipher':"
    echo "----------------------------------------"
    echo "$output"
    echo "----------------------------------------"

    # Check if handshake completed successfully
    # Successful handshakes show "New, TLSv1.2" or "New, TLSv1.3" with a cipher
    # Failed handshakes show "New, (NONE), Cipher is (NONE)" or "Cipher : 0000"
    if echo "$output" | grep -qE "New, TLSv[0-9]"; then
        # Verify the cipher was actually used and is not (NONE)
        if echo "$output" | grep -qiE "Cipher is.*$cipher|Cipher\s*:.*$cipher" && \
           ! echo "$output" | grep -qiE "Cipher is.*\(NONE\)|Cipher\s*:\s*0000"; then
            return 0
        fi
    fi

    return 1
}

# Test TLS 1.2 FIPS ciphers
echo "--- Testing TLS 1.2 FIPS-compliant cipher suites ---"
TLS12_FIPS_PASSED=0
for cipher in "${FIPS_TLS12_CIPHERS[@]}"; do
    if test_cipher "1.2" "$cipher"; then
        echo "✓ TLS 1.2 FIPS cipher '$cipher': SUCCESS"
        TLS12_FIPS_PASSED=$((TLS12_FIPS_PASSED + 1))
    else
        echo "✗ TLS 1.2 FIPS cipher '$cipher': FAILED"
    fi
done

# In FIPS mode, require at least one TLS 1.2 FIPS cipher to work.
# We can't require ALL TLS 1.2 FIPS ciphers because certificate type determines which ones work:
# - RSA certificates: only RSA-based ciphers (ECDHE-RSA-*) work
# - ECDSA certificates: only ECDSA-based ciphers (ECDHE-ECDSA-*) work
# If none work, it indicates a configuration issue or a certificate mismatch.
if [[ "$MODE" == "fips" ]] && [[ $TLS12_FIPS_PASSED -eq 0 ]]; then
    echo ""
    echo "✗ ERROR: No TLS 1.2 FIPS-compliant cipher suites work (expected at least 1)"
    echo "  This may indicate a certificate mismatch or configuration issue"
    exit 1
fi

# Test TLS 1.3 FIPS ciphers - all must work in both FIPS and non-FIPS modes
echo ""
echo "--- Testing TLS 1.3 FIPS-compliant cipher suites ---"
TLS13_FIPS_PASSED=0
for cipher in "${FIPS_TLS13_CIPHERS[@]}"; do
    if test_cipher "1.3" "$cipher"; then
        echo "✓ TLS 1.3 FIPS cipher '$cipher': SUCCESS"
        TLS13_FIPS_PASSED=$((TLS13_FIPS_PASSED + 1))
    else
        echo "✗ TLS 1.3 FIPS cipher '$cipher': FAILED"
        echo ""
        echo "✗ ERROR: Required TLS 1.3 FIPS cipher '$cipher' failed"
        echo "  TLS 1.3 FIPS ciphers must work in both FIPS and non-FIPS modes"
        echo "  This may indicate a configuration issue (e.g., TLS 1.3 disabled)"
        exit 1
    fi
done

# Test TLS 1.2 non-FIPS ciphers - must fail in FIPS mode
echo ""
echo "--- Testing TLS 1.2 non-FIPS cipher suites ---"
for cipher in "${NON_FIPS_TLS12_CIPHERS[@]}"; do
    if test_cipher "1.2" "$cipher"; then
        echo "✗ TLS 1.2 non-FIPS cipher '$cipher': SUCCESS (should fail in FIPS mode)"
        if [[ "$MODE" == "fips" ]]; then
            echo ""
            echo "✗ ERROR: Non-FIPS cipher '$cipher' was accepted (should be rejected in FIPS mode)"
            exit 1
        fi
    else
        echo "✓ TLS 1.2 non-FIPS cipher '$cipher': FAILED (expected in FIPS mode)"
    fi
done

# Test TLS 1.3 non-FIPS ciphers - must fail in FIPS mode
echo ""
echo "--- Testing TLS 1.3 non-FIPS cipher suites ---"
for cipher in "${NON_FIPS_TLS13_CIPHERS[@]}"; do
    if test_cipher "1.3" "$cipher"; then
        echo "✗ TLS 1.3 non-FIPS cipher '$cipher': SUCCESS (should fail in FIPS mode)"
        if [[ "$MODE" == "fips" ]]; then
            echo ""
            echo "✗ ERROR: Non-FIPS cipher '$cipher' was accepted (should be rejected in FIPS mode)"
            exit 1
        fi
    else
        echo "✓ TLS 1.3 non-FIPS cipher '$cipher': FAILED (expected in FIPS mode)"
    fi
done

echo ""
echo "=== Verification Results ==="

# Summary for FIPS mode
if [[ "$MODE" == "fips" ]]; then
    echo "FIPS Mode: Summary..."
    echo "  TLS 1.2 FIPS: $TLS12_FIPS_PASSED/${#FIPS_TLS12_CIPHERS[@]} passed (at least 1 required)"
    echo "  TLS 1.3 FIPS: $TLS13_FIPS_PASSED/${#FIPS_TLS13_CIPHERS[@]} passed (all required)"
    echo ""
    echo "Note: TLS 1.2 cipher suites depend on certificate type:"
    echo "      - RSA certificates: only RSA-based ciphers (ECDHE-RSA-*) work"
    echo "      - ECDSA certificates: only ECDSA-based ciphers (ECDHE-ECDSA-*) work"
    echo "      - TLS 1.3 cipher suites work with any certificate type"
    echo "Note: All non-FIPS cipher suites were correctly rejected"
fi

# Summary for non-FIPS mode
if [[ "$MODE" == "non-fips" ]]; then
    echo "Non-FIPS Mode: Summary..."
    echo "  TLS 1.2 FIPS: $TLS12_FIPS_PASSED/${#FIPS_TLS12_CIPHERS[@]} passed"
    echo "  TLS 1.3 FIPS: $TLS13_FIPS_PASSED/${#FIPS_TLS13_CIPHERS[@]} passed"
    echo ""
    echo "Note: Non-FIPS mode should accept both FIPS and non-FIPS cipher suites"
    echo "Note: TLS 1.2 cipher suites depend on certificate type:"
    echo "      - RSA certificates: only RSA-based ciphers (ECDHE-RSA-*) work"
    echo "      - ECDSA certificates: only ECDSA-based ciphers (ECDHE-ECDSA-*) work"
    echo "      - TLS 1.3 cipher suites work with any certificate type"
fi

echo ""
echo "=== All checks passed ==="
exit 0
