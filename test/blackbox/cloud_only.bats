# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-cloud-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_cloud
load helpers_wait

function setup() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi

    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local zot_openid_credentials_file=${BATS_FILE_TMPDIR}/openid_credentials.json

    cat > ${zot_openid_credentials_file}<<EOF
{
    "clientid": "zot-client",
    "clientsecret": "ZXhhbXBsZS1hcHAtc2VjcmV0"
}
EOF

    echo ${zot_root_dir} >&3

    mkdir -p ${zot_root_dir}

    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}",
        "dedupe": true,
        "remoteCache": true,
        "storageDriver": {
            "name": "s3",
            "rootdirectory": "/zot",
            "region": "us-east-2",
            "regionendpoint": "localhost:4566",
            "bucket": "zot-storage",
            "secure": false,
            "skipverify": false
        },
        "cacheDriver": {
            "name": "dynamodb",
            "endpoint": "http://localhost:4566",
            "region": "us-east-2",
            "cacheTablename": "BlobTable",
            "repoMetaTablename": "RepoMetadataTable",
            "imageMetaTablename": "ImageMetaTable",
            "repoBlobsInfoTablename": "RepoBlobsInfoTable",
            "userDataTablename": "UserDataTable",
            "apiKeyTablename":"ApiKeyTable",
            "versionTablename": "Version"
        }
    },
    "http": {
        "address": "127.0.0.1",
        "port": "8080",
        "realm": "zot",
        "auth": {
            "openid": {
                "providers": {
                    "oidc": {
                        "issuer": "http://127.0.0.1:5556/dex",
                        "credentialsfile": "${zot_openid_credentials_file}",
                        "scopes": ["openid", "email", "groups"]
                    }
                }
            },
            "failDelay": 5
        },
        "accessControl": {
            "repositories": {
                "**": {
                    "anonymousPolicy": ["read", "create"]
                }
            }
        }
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "metrics": {
            "enable": true,
            "prometheus": {
                "path": "/metrics"
            }
        },
        "search": {
            "enable": true
        },
        "scrub": {
            "enable": true,
            "interval": "24h"
        }
    }
}
EOF
    awslocal s3 --region "us-east-2" mb s3://zot-storage
    awslocal dynamodb --region "us-east-2" create-table --table-name "BlobTable" --attribute-definitions AttributeName=Digest,AttributeType=S --key-schema AttributeName=Digest,KeyType=HASH --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=5
    zot_serve_strace ${zot_config_file}
    wait_zot_reachable 8080
}

function teardown() {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    zot_stop
    rm -rf ${zot_root_dir}
    awslocal s3 rb s3://"zot-storage" --force
    awslocal dynamodb --region "us-east-2" delete-table --table-name "BlobTable"
}

dex_session () {
    STATE=$(curl -L -f -s http://localhost:8080/zot/auth/login?provider=oidc | grep -m 1 -oP '(?<=state=)[^ ]*"' | cut -d \" -f1)
    echo $STATE >&3
    curl -L -f -s "http://127.0.0.1:5556/dex/auth/mock?client_id=zot-client&redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fzot%2Fauth%2Fcallback%2Foidc&response_type=code&scope=profile+email+groups+openid&state=$STATE"
}

@test "check dex is working" {
    run dex_session
    [ "$status" -eq 0 ]
}

@test "check for local disk writes" {
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        docker://ghcr.io/project-zot/test-images/centos:8 docker://localhost:8080/centos:8
    [ "$status" -eq 0 ]
    cat strace.txt | grep openat | grep -v O_RDONLY | grep -Eo '\".*\"' | while read -r line ; do
        echo ${line} >&3
        [[ "$line" =~ .*metadata.* || "$line" =~ .*trivy.* ]]
    done
}

# The referrers of an image are found among the other manifests of its
# repository, and nothing else is listed.
@test "list the referrers of an image among unrelated manifests" {
    local repo=127.0.0.1:8080/busybox
    local signature=${BATS_FILE_TMPDIR}/signature.json
    local sbom=${BATS_FILE_TMPDIR}/sbom.json
    local unrelated=${BATS_FILE_TMPDIR}/unrelated.txt

    run skopeo --insecure-policy copy --dest-tls-verify=false \
        docker://ghcr.io/project-zot/test-images/busybox:1.38 docker://${repo}:1.38
    [ "$status" -eq 0 ]

    echo '{"artifact": "signature"}' > ${signature}
    echo '{"artifact": "sbom"}' > ${sbom}

    run oras attach --disable-path-validation --plain-http ${repo}:1.38 \
        --artifact-type 'signature/example' ${signature}:application/json
    [ "$status" -eq 0 ]
    local signature_digest=$(echo "$output" | sed -n 's/^Digest: //p')
    [ -n "${signature_digest}" ]

    # enough manifests for the listing to read them in more than one batch
    for i in $(seq 1 40); do
        echo "unrelated ${i}" > ${unrelated}
        run oras push --disable-path-validation --plain-http ${repo}:unrelated-${i} \
            ${unrelated}:text/plain
        [ "$status" -eq 0 ]
    done

    # a referrer of another manifest of the repository
    run oras attach --disable-path-validation --plain-http ${repo}:unrelated-1 \
        --artifact-type 'signature/example' ${signature}:application/json
    [ "$status" -eq 0 ]

    run oras attach --disable-path-validation --plain-http ${repo}:1.38 \
        --artifact-type 'sbom/example' ${sbom}:application/json
    [ "$status" -eq 0 ]
    local sbom_digest=$(echo "$output" | sed -n 's/^Digest: //p')
    [ -n "${sbom_digest}" ]

    local subject=$(skopeo inspect --tls-verify=false docker://${repo}:1.38 | jq -r '.Digest')
    run curl -s -f http://127.0.0.1:8080/v2/busybox/referrers/${subject}
    [ "$status" -eq 0 ]
    local listed=$(echo "$output" | jq -r '.manifests[].digest' | sort)
    local attached=$(printf '%s\n' "${signature_digest}" "${sbom_digest}" | sort)
    [ "${listed}" = "${attached}" ]
}
