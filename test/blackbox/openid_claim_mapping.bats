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

DEX_CONTAINER_NAME="dex_oidc_claim_mapping_test"

function setup_file() {
    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Pre-allocate all ports we'll need
    dex_port=$(get_free_port_for_service "dex")
    zot_port_1=$(get_free_port_for_service "zot_preferred_username")
    zot_port_2=$(get_free_port_for_service "zot_email")
    zot_port_3=$(get_free_port_for_service "zot_sub")
    zot_port_4=$(get_free_port_for_service "zot_default")
    
    echo ${dex_port} > ${BATS_FILE_TMPDIR}/dex.port

    # Setup dex OIDC provider
    local dex_config_file=${BATS_FILE_TMPDIR}/dex_config.yaml

    # Create dex config with mockCallback connector and all redirect URIs
    cat > ${dex_config_file}<<EOF
issuer: http://127.0.0.1:${dex_port}/dex

storage:
  type: memory

web:
  http: 0.0.0.0:${dex_port}

staticClients:
  - id: zot-client
    redirectURIs:
      - 'http://127.0.0.1:${zot_port_1}/zot/auth/callback/oidc'
      - 'http://127.0.0.1:${zot_port_2}/zot/auth/callback/oidc'
      - 'http://127.0.0.1:${zot_port_3}/zot/auth/callback/oidc'
      - 'http://127.0.0.1:${zot_port_4}/zot/auth/callback/oidc'
    name: 'zot'
    secret: ZXhhbXBsZS1hcHAtc2VjcmV0

connectors:
  - type: mockCallback
    id: mock
    name: Example

enablePasswordDB: true
EOF

    echo "Starting dex on port ${dex_port}..." >&3
    echo "Zot ports will be: ${zot_port_1}, ${zot_port_2}, ${zot_port_3}, ${zot_port_4}" >&3

    # Start dex in docker container
    docker run -d --name ${DEX_CONTAINER_NAME} \
        -p ${dex_port}:${dex_port} \
        -v ${dex_config_file}:/etc/dex/config.yaml \
        ghcr.io/dexidp/dex:v2.37.0 \
        dex serve /etc/dex/config.yaml

    # Wait for dex to be ready
    echo "Waiting for dex to be ready on port ${dex_port}..." >&3
    local dex_url=http://127.0.0.1:${dex_port}/dex/.well-known/openid-configuration
    local max_attempts=60
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl -f -s -o /dev/null ${dex_url} 2>&1; then
            echo "Dex is ready!" >&3
            break
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    
    if [ $attempt -eq $max_attempts ]; then
        echo "Dex failed to start within timeout" >&3
        docker logs ${DEX_CONTAINER_NAME} >&3
        return 1
    fi
}

function teardown_file() {
    zot_stop_all
    docker stop ${DEX_CONTAINER_NAME} 2>/dev/null || true
    docker rm ${DEX_CONTAINER_NAME} 2>/dev/null || true
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
}

function dex_session() {
    local zot_port=${1}
    local dex_port=$(cat ${BATS_FILE_TMPDIR}/dex.port)
    
    STATE=$(curl -L -f -s http://localhost:${zot_port}/zot/auth/login?provider=oidc | grep -m 1 -oP '(?<=state=)[^ ]*"' | cut -d \" -f1)
    echo "STATE: $STATE" >&3
    
    RESPONSE=$(curl -L -f -s "http://127.0.0.1:${dex_port}/dex/auth/mock?client_id=zot-client&redirect_uri=http%3A%2F%2F127.0.0.1%3A${zot_port}%2Fzot%2Fauth%2Fcallback%2Foidc&response_type=code&scope=profile+email+groups+openid&state=$STATE")
    echo "$RESPONSE"
}

@test "test OIDC claim mapping with preferred_username" {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot-preferred-username
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config_preferred_username.json
    local zot_credentials_file=${BATS_FILE_TMPDIR}/zot_credentials_preferred_username.json
    local dex_port=$(cat ${BATS_FILE_TMPDIR}/dex.port)
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
                        "name": "Dex",
                        "issuer": "http://127.0.0.1:${dex_port}/dex",
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
                            "users": ["admin"],
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

    run dex_session ${zot_port}
    [ "$status" -eq 0 ]
    
    # Verify that the log contains the preferred_username claim being used
    run grep -i "preferred_username\|admin" ${BATS_FILE_TMPDIR}/zot-preferred-username.log
    [ "$status" -eq 0 ]
}

@test "test OIDC claim mapping with email" {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot-email
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config_email.json
    local zot_credentials_file=${BATS_FILE_TMPDIR}/zot_credentials_email.json
    local dex_port=$(cat ${BATS_FILE_TMPDIR}/dex.port)
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
                        "name": "Dex",
                        "issuer": "http://127.0.0.1:${dex_port}/dex",
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
                            "users": ["admin@example.com"],
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

    run dex_session ${zot_port}
    [ "$status" -eq 0 ]
    
    # Verify that the log contains email claim being used
    run grep -i "email" ${BATS_FILE_TMPDIR}/zot-email.log
    [ "$status" -eq 0 ]
}

@test "test OIDC claim mapping with sub" {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot-sub
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config_sub.json
    local zot_credentials_file=${BATS_FILE_TMPDIR}/zot_credentials_sub.json
    local dex_port=$(cat ${BATS_FILE_TMPDIR}/dex.port)
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
                        "name": "Dex",
                        "issuer": "http://127.0.0.1:${dex_port}/dex",
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

    run dex_session ${zot_port}
    [ "$status" -eq 0 ]
    
    # Verify that the log contains sub claim being used
    run grep -i "\"sub\"" ${BATS_FILE_TMPDIR}/zot-sub.log
    [ "$status" -eq 0 ]
}

@test "test OIDC with no claim mapping (default to email)" {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot-default
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config_default.json
    local zot_credentials_file=${BATS_FILE_TMPDIR}/zot_credentials_default.json
    local dex_port=$(cat ${BATS_FILE_TMPDIR}/dex.port)
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
                        "name": "Dex",
                        "issuer": "http://127.0.0.1:${dex_port}/dex",
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
                            "users": ["admin@example.com"],
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
        "output": "${BATS_FILE_TMPDIR}/zot-default.log"
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}

    run dex_session ${zot_port}
    [ "$status" -eq 0 ]
    
    # Verify that the log contains email claim being used (default behavior)
    run grep -i "email" ${BATS_FILE_TMPDIR}/zot-default.log
    [ "$status" -eq 0 ]
}
