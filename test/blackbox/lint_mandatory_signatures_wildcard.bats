# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load ../port_helper

function verify_prerequisites() {
    if [ ! $(command -v oras) ]; then
        echo "you need to install oras as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function setup_file() {
    if ! $(verify_prerequisites); then
        exit 1
    fi
}

function teardown() {
    zot_stop_all
}

function run_mandatory_signatures_wildcard_test() {
    local wildcard="$1"
    local suffix="$2"
    local test_dir="${BATS_FILE_TMPDIR}/${suffix}"
    local zot_root_dir="${test_dir}/zot"
    local zot_config_file="${test_dir}/zot_config.json"
    local zot_log_file="${test_dir}/zot.log"

    mkdir -p "${zot_root_dir}"

    local zot_port
    zot_port=$(get_free_port_for_service "zot")

    cat > "${zot_config_file}"<<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}"
    },
    "log": {
        "level": "debug",
        "output": "${zot_log_file}"
    },
    "extensions": {
        "lint": {
            "enable": true,
            "mandatorySignatures": ["${wildcard}"]
        }
    }
}
EOF

    zot_serve "${ZOT_PATH}" "${zot_config_file}"
    wait_zot_reachable "${zot_port}"

    echo '{}' > "${test_dir}/config.json"
    echo "this is a test artifact" > "${test_dir}/artifact.txt"

    run oras push --plain-http 127.0.0.1:${zot_port}/wildcard-${suffix}:v0 \
        --config "${test_dir}/config.json:application/vnd.oci.image.config.v1+json" \
        "${test_dir}/artifact.txt:text/plain" -d -v

    [ "$status" -ne 0 ]
    run grep -q "requires a configured trust store" "${zot_log_file}"
    [ "$status" -eq 0 ]
}

@test "mandatory signatures wildcard '*' applies to all repositories" {
    run_mandatory_signatures_wildcard_test "*" "star"
}

@test "mandatory signatures wildcard '**' applies to all repositories" {
    run_mandatory_signatures_wildcard_test "**" "double-star"
}
