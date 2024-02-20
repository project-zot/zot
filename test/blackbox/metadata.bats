# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot

function verify_prerequisites {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v jq) ]; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v htpasswd) ]; then
        echo "you need to install htpasswd as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function setup_file() {
    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/test-images/busybox:1.36 oci:${TEST_DATA_DIR}/busybox:1.36

    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    local zot_htpasswd_file=${BATS_FILE_TMPDIR}/htpasswd
    mkdir -p ${zot_root_dir}
    mkdir -p ${oci_data_dir}
    zot_port=$(get_free_port)
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    htpasswd -Bbn ${AUTH_USER} ${AUTH_PASS} >> ${zot_htpasswd_file}
    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "extensions": {
        "search": {
            "enable": true
        },
        "ui": {
            "enable": true
        }
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_port}",
        "auth": {
            "htpasswd": {
                "path": "${zot_htpasswd_file}"
            }
        },
        "accessControl": {
            "repositories": {
                "**": {
                    "anonymousPolicy": ["read"],
                    "policies": [
                        {
                            "users": [
                                "${AUTH_USER}"
                            ],
                            "actions": [
                                "read",
                                "create",
                                "update"
                            ]
                        }
                    ]
                }
            }
        }
    },
    "log": {
        "level": "debug",
        "output": "${BATS_FILE_TMPDIR}/zot.log"
    }
}
EOF
    git -C ${BATS_FILE_TMPDIR} clone https://github.com/project-zot/helm-charts.git
    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}
}

function teardown() {
    # conditionally printing on failure is possible from teardown but not from from teardown_file
    cat ${BATS_FILE_TMPDIR}/zot.log
}

function teardown_file() {
    zot_stop_all
}

@test "push image user policy" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --dest-creds ${AUTH_USER}:${AUTH_PASS} --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/busybox:1.36 \
        docker://127.0.0.1:${zot_port}/busybox:1.36
    [ "$status" -eq 0 ]
}

@test "User metadata starredRepos" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --dest-creds ${AUTH_USER}:${AUTH_PASS} --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/busybox:1.36 \
        docker://127.0.0.1:${zot_port}/busybox:1.36
    [ "$status" -eq 0 ]

    USER_STAR_REPOS_QUERY='{ "query": "{ StarredRepos { Results { Name } } }"}'

    run curl --user ${AUTH_USER}:${AUTH_PASS} -X POST -H "Content-Type: application/json" --data "${USER_STAR_REPOS_QUERY}" http://localhost:${zot_port}/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.data.StarredRepos.Results') = '[]' ]

    run curl --user ${AUTH_USER}:${AUTH_PASS} -X PUT "http://127.0.0.1:${zot_port}/v2/_zot/ext/userprefs?repo=busybox&action=toggleStar"
    [ "$status" -eq 0 ]

    run curl --user ${AUTH_USER}:${AUTH_PASS} -X POST -H "Content-Type: application/json" --data "${USER_STAR_REPOS_QUERY}" http://localhost:${zot_port}/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    echo  $(echo "${lines[-1]}" | jq '.data.StarredRepos.Results[0].Name')
    [ $(echo "${lines[-1]}" | jq -r '.data.StarredRepos.Results[0].Name') = 'busybox' ]

    run curl --user ${AUTH_USER}:${AUTH_PASS} -X PUT "http://127.0.0.1:${zot_port}/v2/_zot/ext/userprefs?repo=busybox&action=toggleStar"
    [ "$status" -eq 0 ]

        run curl --user ${AUTH_USER}:${AUTH_PASS} -X POST -H "Content-Type: application/json" --data "${USER_STAR_REPOS_QUERY}" http://localhost:${zot_port}/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    echo  $(echo "${lines[-1]}" | jq '.data.StarredRepos.Results')
    [ $(echo "${lines[-1]}" | jq -r '.data.StarredRepos.Results') = '[]' ]
}

@test "User metadata bookmarkedRepos" {
    zot_port=`cat ${BATS_FILE_TMPDIR}/zot.port`
    run skopeo --insecure-policy copy --dest-creds ${AUTH_USER}:${AUTH_PASS} --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/busybox:1.36 \
        docker://127.0.0.1:${zot_port}/busybox:1.36
    [ "$status" -eq 0 ]

    USER_BOOKMARK_REPOS_QUERY='{ "query": "{ BookmarkedRepos { Results { Name } } }"}'

     run curl --user ${AUTH_USER}:${AUTH_PASS} -X POST -H "Content-Type: application/json" --data "${USER_BOOKMARK_REPOS_QUERY}" http://localhost:${zot_port}/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.data.BookmarkedRepos.Results') = '[]' ]

    run curl --user ${AUTH_USER}:${AUTH_PASS} -X PUT "http://127.0.0.1:${zot_port}/v2/_zot/ext/userprefs?repo=busybox&action=toggleBookmark"
    [ "$status" -eq 0 ]

    run curl --user ${AUTH_USER}:${AUTH_PASS} -X POST -H "Content-Type: application/json" --data "${USER_BOOKMARK_REPOS_QUERY}" http://localhost:${zot_port}/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq -r '.data.BookmarkedRepos.Results[0].Name') = 'busybox' ]

    run curl --user ${AUTH_USER}:${AUTH_PASS} -X PUT "http://127.0.0.1:${zot_port}/v2/_zot/ext/userprefs?repo=busybox&action=toggleBookmark"
    [ "$status" -eq 0 ]

        run curl --user ${AUTH_USER}:${AUTH_PASS} -X POST -H "Content-Type: application/json" --data "${USER_BOOKMARK_REPOS_QUERY}" http://localhost:${zot_port}/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq -r '.data.BookmarkedRepos.Results') = '[]' ]
}
