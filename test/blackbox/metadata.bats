load helpers_pushpull

function setup_file() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi

    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.18 oci:${TEST_DATA_DIR}/golang:1.18
    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    local htpasswordFile=${BATS_FILE_TMPDIR}/htpasswd
    mkdir -p ${zot_root_dir}
    mkdir -p ${oci_data_dir}
    echo 'test:$2a$10$EIIoeCnvsIDAJeDL4T1sEOnL2fWOvsq7ACZbs3RT40BBBXg.Ih7V.' >> ${htpasswordFile}
    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "extensions": {
        "search": {
            "enable": true
        }
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8080",
        "auth": {
            "htpasswd": {
                "path": "${htpasswordFile}"
            }
        },
        "accessControl": {
            "repositories": {
                "**": {
                    "anonymousPolicy": ["read"],
                    "policies": [
                        {
                            "users": [
                                "test"
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
        "level": "debug"
    }
}
EOF
    git -C ${BATS_FILE_TMPDIR} clone https://github.com/project-zot/helm-charts.git
    setup_zot_file_level ${zot_config_file}
    wait_zot_reachable "http://127.0.0.1:8080/v2/_catalog"
}

function teardown_file() {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    teardown_zot_file_level
    rm -rf ${zot_root_dir}
    rm -rf ${oci_data_dir}
}


@test "push image user policy" {
    run skopeo --insecure-policy copy --dest-creds test:test --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.18 \
        docker://127.0.0.1:8080/golang:1.18
    [ "$status" -eq 0 ]
}

@test "User metadata starredRepos" {
    run skopeo --insecure-policy copy --dest-creds test:test --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.18 \
        docker://127.0.0.1:8080/golang:1.18
    [ "$status" -eq 0 ]

    USER_STAR_REPOS_QUERY='{ "query": "{ StarredRepos { Results { Name } } }"}'

    run curl --user "test:test" -X POST -H "Content-Type: application/json" --data "${USER_STAR_REPOS_QUERY}" http://localhost:8080/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.data.StarredRepos.Results') = '[]' ]

    run curl --user "test:test" -X PUT "http://127.0.0.1:8080/v2/_zot/ext/userprefs?repo=golang&action=toggleStar"
    [ "$status" -eq 0 ]

    run curl --user "test:test" -X POST -H "Content-Type: application/json" --data "${USER_STAR_REPOS_QUERY}" http://localhost:8080/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    echo  $(echo "${lines[-1]}" | jq '.data.StarredRepos.Results[0].Name')
    [ $(echo "${lines[-1]}" | jq -r '.data.StarredRepos.Results[0].Name') = 'golang' ]

    run curl --user "test:test" -X PUT "http://127.0.0.1:8080/v2/_zot/ext/userprefs?repo=golang&action=toggleStar"
    [ "$status" -eq 0 ]

        run curl --user "test:test" -X POST -H "Content-Type: application/json" --data "${USER_STAR_REPOS_QUERY}" http://localhost:8080/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    echo  $(echo "${lines[-1]}" | jq '.data.StarredRepos.Results')
    [ $(echo "${lines[-1]}" | jq -r '.data.StarredRepos.Results') = '[]' ]
}

@test "User metadata bookmarkedRepos" {
    run skopeo --insecure-policy copy --dest-creds test:test --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.18 \
        docker://127.0.0.1:8080/golang:1.18
    [ "$status" -eq 0 ]

    USER_BOOKMARK_REPOS_QUERY='{ "query": "{ BookmarkedRepos { Results { Name } } }"}'

     run curl --user "test:test" -X POST -H "Content-Type: application/json" --data "${USER_BOOKMARK_REPOS_QUERY}" http://localhost:8080/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.data.BookmarkedRepos.Results') = '[]' ]

    run curl --user "test:test" -X PUT "http://127.0.0.1:8080/v2/_zot/ext/userprefs?repo=golang&action=toggleBookmark"
    [ "$status" -eq 0 ]

    run curl --user "test:test" -X POST -H "Content-Type: application/json" --data "${USER_BOOKMARK_REPOS_QUERY}" http://localhost:8080/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq -r '.data.BookmarkedRepos.Results[0].Name') = 'golang' ]

    run curl --user "test:test" -X PUT "http://127.0.0.1:8080/v2/_zot/ext/userprefs?repo=golang&action=toggleBookmark"
    [ "$status" -eq 0 ]

        run curl --user "test:test" -X POST -H "Content-Type: application/json" --data "${USER_BOOKMARK_REPOS_QUERY}" http://localhost:8080/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq -r '.data.BookmarkedRepos.Results') = '[]' ]
}
