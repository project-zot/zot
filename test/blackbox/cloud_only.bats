# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-cloud-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_cloud
load helpers_wait

function setup() {
    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json

    echo ${zot_root_dir} >&3

    mkdir -p ${zot_root_dir}

    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.0",
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
                        "clientid": "zot-client",
                        "clientsecret": "ZXhhbXBsZS1hcHAtc2VjcmV0",
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
        docker://centos:centos8 docker://localhost:8080/centos:8
    [ "$status" -eq 0 ]
    cat strace.txt | grep openat | grep -v O_RDONLY | grep -Eo '\".*\"' | while read -r line ; do
        echo ${line} >&3
        [[ "$line" =~ .*metadata.* || "$line" =~ .*trivy.* ]]
    done
}
