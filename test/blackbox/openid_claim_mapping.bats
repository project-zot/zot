# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_wait
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

    if [ ! $(command -v docker) ]; then
        echo "you need to install docker as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

IDP_PID=""

function setup_file() {
    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Pre-allocate all ports we'll need
    idp_port=$(get_free_port_for_service "idp")
    echo ${idp_port} > ${BATS_FILE_TMPDIR}/idp.port

    # Setup oidc provider
    npm link oidc-provider express
    node ${ROOT_DIR}/test/scripts/panva-idp.js ${idp_port} > ${BATS_FILE_TMPDIR}/idp.log 2>&1 &
    IDP_PID=$!

    # Wait for oidc provider to be ready
    echo "Waiting for idp to be ready on port ${idp_port}..." >&3
    local idp_url=http://127.0.0.1:${idp_port}/.well-known/openid-configuration
    local max_attempts=60
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl -f -s -o /dev/null ${idp_url} 2>&1; then
            echo "oidc idp is ready!" >&3
            break
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    
    if [ $attempt -eq $max_attempts ]; then
        echo "idp failed to start within timeout" >&3
        return 1
    fi
}

function teardown_file() {
    zot_stop_all
    kill ${IDP_PID}
    if [ -f "${BATS_FILE_TMPDIR}/idp.log" ]; then
        echo "--- IDP LOG ---"
        cat ${BATS_FILE_TMPDIR}/idp.log
        echo "--- END IDP LOG ---"
    fi
}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from teardown_file
    if [ -f "${BATS_FILE_TMPDIR}/zot-preferred-username.log" ]; then
        cat ${BATS_FILE_TMPDIR}/zot-preferred-username.log
    fi
    if [ -f "${BATS_FILE_TMPDIR}/zot-email.log" ]; then
        cat ${BATS_FILE_TMPDIR}/zot-email.log
    fi
    if [ -f "${BATS_FILE_TMPDIR}/zot-sub.log" ]; then
        cat ${BATS_FILE_TMPDIR}/zot-sub.log
    fi
    if [ -f "${BATS_FILE_TMPDIR}/zot-default.log" ]; then
        cat ${BATS_FILE_TMPDIR}/zot-default.log
    fi
    if [ -f "${BATS_FILE_TMPDIR}/idp.log" ]; then
        echo "--- IDP LOG (teardown) ---"
        cat ${BATS_FILE_TMPDIR}/idp.log
        echo "--- END IDP LOG ---"
    fi
}

function idp_session() {
    local zot_port=${1}
    local idp_port=$(cat ${BATS_FILE_TMPDIR}/idp.port)
    
    # With the auto-login enabled IDP, we just need to hit the login endpoint and follow redirects.
    # We use a cookie jar to handle the session cookies during the redirects.
    curl -v -L -c ${BATS_FILE_TMPDIR}/cookies "http://127.0.0.1:${zot_port}/zot/auth/login?provider=oidc"
}

@test "test OIDC claim mapping with preferred_username" {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot-preferred-username
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config_preferred_username.json
    local zot_credentials_file=${BATS_FILE_TMPDIR}/zot_credentials_preferred_username.json
    local idp_port=$(cat ${BATS_FILE_TMPDIR}/idp.port)
    zot_port=$(get_free_port_for_service "zot_preferred_username")

    mkdir -p ${zot_root_dir}

    cat > ${zot_credentials_file}<<EOF
{
    "clientid": "zot-client",
    "clientsecret": "ZXhhbXBsZS1hcHAtc2VjcmV0"
}
EOF

    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}",
        "dedupe": true
    },
    "http": {
        "address": "127.0.0.1",
        "port": "${zot_port}",
        "realm": "zot",
        "auth": {
            "openid": {
                "providers": {
                    "oidc": {
                        "name": "panva",
                        "issuer": "http://127.0.0.1:${idp_port}/",
                        "credentialsFile": "${zot_credentials_file}",
                        "scopes": ["openid", "profile", "email", "groups"],
                        "claimMapping": {
                            "username": "preferred_username"
                        }
                    }
                }
            },
            "failDelay": 5
        },
        "accessControl": {
            "repositories": {
                "**": {
                    "policies": [
                        {
                            "users": ["alice"],
                            "actions": ["read", "create", "update", "delete"]
                        }
                    ],
                    "defaultPolicy": ["read"]
                }
            }
        }
    },
    "log": {
        "level": "debug",
        "output": "${BATS_FILE_TMPDIR}/zot-preferred-username.log"
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}

    run idp_session ${zot_port}
    [ "$status" -eq 0 ]
    echo "$output"
    
    # Verify that the log contains the preferred_username claim being used
    log_output ${BATS_FILE_TMPDIR}/zot-preferred-username.log | jq 'contains("extracted username from configured claim")' | grep true
    log_output ${BATS_FILE_TMPDIR}/zot-preferred-username.log | jq 'contains("using email as username (fallback)") | not' | grep true
}

@test "test OIDC claim mapping with email" {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot-email
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config_email.json
    local zot_credentials_file=${BATS_FILE_TMPDIR}/zot_credentials_email.json
    local idp_port=$(cat ${BATS_FILE_TMPDIR}/idp.port)
    zot_port=$(get_free_port_for_service "zot_email")

    mkdir -p ${zot_root_dir}

    cat > ${zot_credentials_file}<<EOF
{
    "clientid": "zot-client",
    "clientsecret": "ZXhhbXBsZS1hcHAtc2VjcmV0"
}
EOF

    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}",
        "dedupe": true
    },
    "http": {
        "address": "127.0.0.1",
        "port": "${zot_port}",
        "realm": "zot",
        "auth": {
            "openid": {
                "providers": {
                    "oidc": {
                        "name": "panva",
                        "issuer": "http://127.0.0.1:${idp_port}/",
                        "credentialsFile": "${zot_credentials_file}",
                        "scopes": ["openid", "profile", "email", "groups"],
                        "claimMapping": {
                            "username": "email"
                        }
                    }
                }
            },
            "failDelay": 5
        },
        "accessControl": {
            "repositories": {
                "**": {
                    "policies": [
                        {
                            "users": ["alice@example.com"],
                            "actions": ["read", "create", "update", "delete"]
                        }
                    ],
                    "defaultPolicy": ["read"]
                }
            }
        }
    },
    "log": {
        "level": "debug",
        "output": "${BATS_FILE_TMPDIR}/zot-email.log"
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}

    run idp_session ${zot_port}
    [ "$status" -eq 0 ]
    echo "$output"
    
    # Verify that the log contains email claim being used
    log_output ${BATS_FILE_TMPDIR}/zot-email.log | jq 'contains("extracted username from configured claim")' | grep true
    log_output ${BATS_FILE_TMPDIR}/zot-email.log | jq 'contains("using email as username (fallback)") | not' | grep true
}

@test "test OIDC claim mapping with sub" {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot-sub
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config_sub.json
    local zot_credentials_file=${BATS_FILE_TMPDIR}/zot_credentials_sub.json
    local idp_port=$(cat ${BATS_FILE_TMPDIR}/idp.port)
    zot_port=$(get_free_port_for_service "zot_sub")

    mkdir -p ${zot_root_dir}

    cat > ${zot_credentials_file}<<EOF
{
    "clientid": "zot-client",
    "clientsecret": "ZXhhbXBsZS1hcHAtc2VjcmV0"
}
EOF

    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}",
        "dedupe": true
    },
    "http": {
        "address": "127.0.0.1",
        "port": "${zot_port}",
        "realm": "zot",
        "auth": {
            "openid": {
                "providers": {
                    "oidc": {
                        "name": "panva",
                        "issuer": "http://127.0.0.1:${idp_port}/",
                        "credentialsFile": "${zot_credentials_file}",
                        "scopes": ["openid", "profile", "email", "groups"],
                        "claimMapping": {
                            "username": "sub"
                        }
                    }
                }
            },
            "failDelay": 5
        },
        "accessControl": {
            "repositories": {
                "**": {
                    "defaultPolicy": ["read"]
                }
            }
        }
    },
    "log": {
        "level": "debug",
        "output": "${BATS_FILE_TMPDIR}/zot-sub.log"
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}

    run idp_session ${zot_port}
    [ "$status" -eq 0 ]
    echo "$output"
    
    # Verify that the log contains sub claim being used
    log_output ${BATS_FILE_TMPDIR}/zot-sub.log | jq 'contains("extracted username from configured claim")' | grep true
    log_output ${BATS_FILE_TMPDIR}/zot-sub.log | jq 'contains("using email as username (fallback)") | not' | grep true
}

@test "test OIDC with no claim mapping (default to email)" {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot-default
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config_default.json
    ZOT_LOG_FILE=${BATS_FILE_TMPDIR}/zot-default.log
    local zot_credentials_file=${BATS_FILE_TMPDIR}/zot_credentials_default.json
    local idp_port=$(cat ${BATS_FILE_TMPDIR}/idp.port)
    zot_port=$(get_free_port_for_service "zot_default")

    mkdir -p ${zot_root_dir}

    cat > ${zot_credentials_file}<<EOF
{
    "clientid": "zot-client",
    "clientsecret": "ZXhhbXBsZS1hcHAtc2VjcmV0"
}
EOF

    # Note: No claimMapping section - should default to email
    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}",
        "dedupe": true
    },
    "http": {
        "address": "127.0.0.1",
        "port": "${zot_port}",
        "realm": "zot",
        "auth": {
            "openid": {
                "providers": {
                    "oidc": {
                        "name": "panva",
                        "issuer": "http://127.0.0.1:${idp_port}/",
                        "credentialsFile": "${zot_credentials_file}",
                        "scopes": ["openid", "profile", "email", "groups"]
                    }
                }
            },
            "failDelay": 5
        },
        "accessControl": {
            "repositories": {
                "**": {
                    "policies": [
                        {
                            "users": ["alice@example.com"],
                            "actions": ["read", "create", "update", "delete"]
                        }
                    ],
                    "defaultPolicy": ["read"]
                }
            }
        }
    },
    "log": {
        "level": "debug",
        "output": "${ZOT_LOG_FILE}"
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}

    run idp_session ${zot_port}
    [ "$status" -eq 0 ]
    echo "$output"
    
    # Verify that the log contains email claim being used (default behavior)
    log_output ${BATS_FILE_TMPDIR}/zot-default.log | jq 'contains("using email as username (fallback)")' | grep true
}
