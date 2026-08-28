# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load ../port_helper

function verify_prerequisites {
    if ! command -v systemd-socket-activate >/dev/null 2>&1; then
        echo "you need to install systemd-socket-activate as a prerequisite to running the tests" >&3
        return 1
    fi

    if ! command -v curl >/dev/null 2>&1; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function wait_socket_activation_ready() {
    local port=${1}
    local url="http://127.0.0.1:${port}/v2/_catalog"
    local max_attempts=20
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        local response
        response=$(curl -sS --connect-timeout 2 --max-time 3 "${url}" 2>/dev/null || true)
        if echo "${response}" | grep -q "\"repositories\""; then
            return 0
        fi
        sleep 0.2
        ((attempt++))
    done

    echo "ERROR: zot socket activation not reachable on port ${port}" >&3
    return 1
}


function wait_for_log() {
    local log_file=${1}
    local pattern=${2}
    # createListener runs only after Init and StartBackgroundTasks. Under
    # parallel blackbox CI that routinely exceeds 5s, so poll longer.
    local max_attempts=300
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if grep -q "${pattern}" "${log_file}" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        ((attempt++))
    done

    echo "ERROR: pattern '${pattern}' not found in ${log_file} after 30 seconds" >&3
    return 1
}


function wait_for_listen() {
    local port=${1}
    local max_attempts=50
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if (echo >"/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
        ((attempt++))
    done

    echo "ERROR: Port ${port} not listening after 5 seconds" >&3
    return 1
}

function setup_file() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi
}

function teardown() {
    zot_stop_all
    pkill -f "${BATS_FILE_TMPDIR}" 2>/dev/null || true

    # Wait for port to be released if recorded
    if [ -f "${BATS_FILE_TMPDIR}/zot.port" ]; then
        local port
        port=$(cat "${BATS_FILE_TMPDIR}/zot.port" 2>/dev/null || true)
        if [ -n "$port" ]; then
            local port_deadline=$((SECONDS + 5))
            while [ $SECONDS -lt $port_deadline ]; do
                (echo >"/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1 || break
                sleep 0.1
            done
        fi
    fi

    # Dump logs if any exist for debugging
    for log_file in "${BATS_FILE_TMPDIR}"/*.log; do
        if [ -f "${log_file}" ]; then
            cat "${log_file}"
        fi
    done
}

function teardown_file() {
    zot_stop_all
    pkill -f "${BATS_FILE_TMPDIR}" 2>/dev/null || true
}

@test "socket activation with matching configured port" {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot-matching
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config_matching.json
    local zot_log_file=${BATS_FILE_TMPDIR}/zot-matching.log
    local port=$(get_free_port_for_service "systemd")

    mkdir -p "${zot_root_dir}"

    cat > "${zot_config_file}" <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "127.0.0.1",
        "port": "${port}"
    },
    "log": {
        "level": "debug",
        "output": "${zot_log_file}"
    }
}
EOF

    systemd-socket-activate --listen="127.0.0.1:${port}" "${ZOT_PATH}" serve "${zot_config_file}" &
    local act_pid=$!
    echo -n "${act_pid} " >> "${BATS_FILE_TMPDIR}/zot.pid"
    echo "${port}" > "${BATS_FILE_TMPDIR}/zot.port"

    # Wait until zot is activated and responding
    wait_socket_activation_ready "${port}"

    # Query the socket-activated zot instance
    run curl -s -f -o /dev/null -w "%{http_code}" "http://127.0.0.1:${port}/v2/"
    [ "$status" -eq 0 ]
    [ "$output" = "200" ]

    # Verify catalog endpoint returns valid response
    run curl -s "http://127.0.0.1:${port}/v2/_catalog"
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "\"repositories\""

    # Verify log output records using systemd socket activation
    grep -q "using systemd socket activation listener" "${zot_log_file}"
}

@test "socket activation with unspecified port (systemd owns the bind)" {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot-unspecified
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config_unspecified.json
    local zot_log_file=${BATS_FILE_TMPDIR}/zot-unspecified.log
    local port=$(get_free_port_for_service "systemd")

    mkdir -p "${zot_root_dir}"

    cat > "${zot_config_file}" <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "127.0.0.1",
        "port": "0"
    },
    "log": {
        "level": "debug",
        "output": "${zot_log_file}"
    }
}
EOF

    systemd-socket-activate --listen="127.0.0.1:${port}" "${ZOT_PATH}" serve "${zot_config_file}" &
    local act_pid=$!
    echo -n "${act_pid} " >> "${BATS_FILE_TMPDIR}/zot.pid"
    echo "${port}" > "${BATS_FILE_TMPDIR}/zot.port"

    # Wait until zot is activated and responding
    wait_socket_activation_ready "${port}"

    # Query the socket-activated zot instance
    run curl -s -f -o /dev/null -w "%{http_code}" "http://127.0.0.1:${port}/v2/"
    [ "$status" -eq 0 ]
    [ "$output" = "200" ]

    # Verify catalog endpoint returns valid response
    run curl -s "http://127.0.0.1:${port}/v2/_catalog"
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "\"repositories\""

    # Verify log output records using systemd socket activation
    grep -q "using systemd socket activation listener" "${zot_log_file}"
}

@test "socket activation fails when configured port mismatches activated port" {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot-mismatch
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config_mismatch.json
    local config_port="5000"
    local activated_port=$(get_free_port_for_service "systemd")

    mkdir -p "${zot_root_dir}"

    cat > "${zot_config_file}" <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "127.0.0.1",
        "port": "${config_port}"
    }
}
EOF

    local act_log="${BATS_FILE_TMPDIR}/systemd-act-mismatch.log"
    systemd-socket-activate --listen="127.0.0.1:${activated_port}" "${ZOT_PATH}" serve "${zot_config_file}" > "${act_log}" 2>&1 &
    local act_pid=$!
    echo -n "${act_pid} " >> "${BATS_FILE_TMPDIR}/zot.pid"
    echo "${activated_port}" > "${BATS_FILE_TMPDIR}/zot.port"

    # Wait for systemd-socket-activate to bind the port before sending traffic
    wait_for_listen "${activated_port}" || true

    # Trigger activation via curl
    curl -s -m 2 "http://127.0.0.1:${activated_port}/v2/" || true

    # Give zot a moment to fail startup and log the error
    # Verify log output contains port mismatch error
    wait_for_log "${act_log}" "systemd activated port does not match configured http port"
}

@test "socket activation fails when port is omitted in config (defaults to 8080)" {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot-omitted-port
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config_omitted.json
    local activated_port=$(get_free_port_for_service "systemd")

    mkdir -p "${zot_root_dir}"

    cat > "${zot_config_file}" <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "127.0.0.1"
    }
}
EOF

    local act_log="${BATS_FILE_TMPDIR}/systemd-act-omitted.log"
    systemd-socket-activate --listen="127.0.0.1:${activated_port}" "${ZOT_PATH}" serve "${zot_config_file}" > "${act_log}" 2>&1 &
    local act_pid=$!
    echo -n "${act_pid} " >> "${BATS_FILE_TMPDIR}/zot.pid"
    echo "${activated_port}" > "${BATS_FILE_TMPDIR}/zot.port"

    # Wait for systemd-socket-activate to bind the port before sending traffic
    wait_for_listen "${activated_port}" || true

    # Trigger activation via curl
    curl -s -m 2 "http://127.0.0.1:${activated_port}/v2/" || true

    # Give zot a moment to fail startup and log the error
    # Verify log output records mismatch against default port 8080
    wait_for_log "${act_log}" "systemd activated port does not match configured http port"
    wait_for_log "${act_log}" "configured port 8080"
}

@test "socket activation fails when multiple listeners are passed" {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot-multi
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config_multi.json
    local port1
    local port2
    port1=$(get_free_port_for_service "systemd")
    port2=$(get_free_port_for_service "systemd")
    while [ "${port2}" = "${port1}" ]; do
        port2=$(get_free_port_for_service "systemd")
    done

    mkdir -p "${zot_root_dir}"

    cat > "${zot_config_file}" <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "127.0.0.1",
        "port": "0"
    }
}
EOF

    local act_log="${BATS_FILE_TMPDIR}/systemd-act-multi.log"
    systemd-socket-activate --listen="127.0.0.1:${port1}" --listen="127.0.0.1:${port2}" "${ZOT_PATH}" serve "${zot_config_file}" > "${act_log}" 2>&1 &
    local act_pid=$!
    echo -n "${act_pid} " >> "${BATS_FILE_TMPDIR}/zot.pid"
    echo "${port1}" > "${BATS_FILE_TMPDIR}/zot.port"

    # Wait for systemd-socket-activate to bind the port before sending traffic
    wait_for_listen "${port1}" || true

    # Trigger activation via curl
    curl -s -m 2 "http://127.0.0.1:${port1}/v2/" || true

    # Give zot a moment to fail startup and log the error
    # Verify log output records error for multiple listeners
    wait_for_log "${act_log}" "expected exactly one systemd socket activation listener"
}
