load helpers_pushpull

function setup_file() {
    # Verify prerequisites are available
    if ! verify_prerequisites; then
        exit 1
    fi
    # Download test data to folder common for the entire suite, not just this file
    skopeo --insecure-policy copy --format=oci docker://ghcr.io/project-zot/golang:1.20 oci:${TEST_DATA_DIR}/golang:1.20
    # Setup zot server
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    mkdir -p ${zot_root_dir}
    mkdir -p ${oci_data_dir}
    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.1.0",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8080"
    },
    "log": {
        "level": "debug"
    },
    "extensions":{
        "search": {
                    "enable": "true"
        },
        "lint": {
                    "enable": "true",
                    "mandatoryAnnotations": ["org.opencontainers.image.licenses", "org.opencontainers.image.vendor"]
        }
    }
}
EOF
    cat > ${BATS_FILE_TMPDIR}/stacker.yaml<<EOF
\${{IMAGE_NAME}}:
  from:
    type: docker
    url: docker://\${{IMAGE_NAME}}:\${{IMAGE_TAG}}
  annotations:
    org.opencontainers.image.title: \${{IMAGE_NAME}}
    org.opencontainers.image.description: \${{DESCRIPTION}}
    org.opencontainers.image.licenses: \${{LICENSES}}
    org.opencontainers.image.vendor: \${{VENDOR}}
EOF
    cat > ${BATS_FILE_TMPDIR}/Dockerfile<<EOF
FROM public.ecr.aws/t0x7q1g8/centos:7
CMD ["/bin/sh", "-c", "echo 'It works!'"]
EOF
    setup_zot_file_level ${zot_config_file}
    wait_zot_reachable "http://127.0.0.1:8080/v2/_catalog"
}

function teardown_file() {
    local zot_root_dir=${BATS_FILE_TMPDIR}/zot
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    local roots_data_dir=${BATS_FILE_TMPDIR}/roots
    local stacker_data_dir=${BATS_FILE_TMPDIR}/.stacker
    local stackeroci_data_dir=${BATS_FILE_TMPDIR}/stackeroci
    teardown_zot_file_level
    rm -rf ${zot_root_dir}
    rm -rf ${oci_data_dir}
    rm -rf ${stackeroci_data_dir}
    rm -rf ${roots_data_dir}    
}

@test "build image with podman and specify annotations" {
    run podman build -f ${BATS_FILE_TMPDIR}/Dockerfile -t 127.0.0.1:8080/annotations:latest . --format oci --annotation org.opencontainers.image.vendor="CentOS" --annotation org.opencontainers.image.licenses="GPLv2"
    [ "$status" -eq 0 ]
    run podman push 127.0.0.1:8080/annotations:latest --tls-verify=false --format=oci
    [ "$status" -eq 0 ]
    run curl -X POST -H "Content-Type: application/json" --data '{ "query": "{ ImageList(repo: \"annotations\") { Results { RepoName Tag Manifests {Digest ConfigDigest Size Layers { Size Digest }} Vendor Licenses }}}"}' http://localhost:8080/v2/_zot/ext/search
   
    [ "$status" -eq 0 ]
    # [ $(echo "${lines[-1]}" | jq '.data.ImageList') ]
    [ $(echo "${lines[-1]}" | jq '.data.ImageList.Results[0].RepoName') = '"annotations"' ]
    [ $(echo "${lines[-1]}" | jq '.data.ImageList.Results[0].Vendor') = '"CentOS"' ]
    [ $(echo "${lines[-1]}" | jq '.data.ImageList.Results[0].Licenses') = '"GPLv2"' ]
}

@test "build image with stacker and specify annotations" {
    run stacker --oci-dir ${BATS_FILE_TMPDIR}/stackeroci --stacker-dir ${BATS_FILE_TMPDIR}/.stacker --roots-dir ${BATS_FILE_TMPDIR}/roots build -f ${BATS_FILE_TMPDIR}/stacker.yaml --substitute IMAGE_NAME="ghcr.io/project-zot/golang" --substitute IMAGE_TAG="1.20" --substitute DESCRIPTION="mydesc" --substitute VENDOR="CentOs" --substitute LICENSES="GPLv2" --substitute COMMIT= --substitute OS=$OS --substitute ARCH=$ARCH
    [ "$status" -eq 0 ]
    run stacker --oci-dir ${BATS_FILE_TMPDIR}/stackeroci --stacker-dir ${BATS_FILE_TMPDIR}/.stacker --roots-dir ${BATS_FILE_TMPDIR}/roots publish -f ${BATS_FILE_TMPDIR}/stacker.yaml --substitute IMAGE_NAME="ghcr.io/project-zot/golang" --substitute IMAGE_TAG="1.20" --substitute DESCRIPTION="mydesc" --substitute VENDOR="CentOs" --substitute LICENSES="GPLv2" --url docker://127.0.0.1:8080 --tag 1.20 --skip-tls
    [ "$status" -eq 0 ]
    run curl -X POST -H "Content-Type: application/json" --data '{ "query": "{ ImageList(repo: \"ghcr.io/project-zot/golang\") { Results { RepoName Tag Manifests {Digest ConfigDigest Size Layers { Size Digest }} Vendor Licenses Description }}}"}' http://localhost:8080/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.data.ImageList.Results[0].RepoName') = '"ghcr.io/project-zot/golang"' ]
    [ $(echo "${lines[-1]}" | jq '.data.ImageList.Results[0].Description') = '"mydesc"' ]
    [ $(echo "${lines[-1]}" | jq '.data.ImageList.Results[0].Vendor') = '"CentOs"' ]
    [ $(echo "${lines[-1]}" | jq '.data.ImageList.Results[0].Licenses') = '"GPLv2"' ]
}

@test "sign/verify with cosign" {
    run curl -X POST -H "Content-Type: application/json" --data '{ "query": "{ ImageList(repo: \"annotations\") { Results { RepoName Tag Manifests {Digest ConfigDigest Size Layers { Size Digest }} Vendor Licenses }}}"}' http://localhost:8080/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.data.ImageList.Results[0].RepoName') = '"annotations"' ]
    local digest=$(echo "${lines[-1]}" | jq -r '.data.ImageList.Results[0].Manifests[0].Digest')
    
    run cosign initialize
    [ "$status" -eq 0 ]
    run cosign generate-key-pair --output-key-prefix "cosign-sign-test"
    [ "$status" -eq 0 ]
    run cosign sign --key cosign-sign-test.key localhost:8080/annotations:latest --yes
    [ "$status" -eq 0 ]
    run cosign verify --key cosign-sign-test.pub localhost:8080/annotations:latest
    [ "$status" -eq 0 ]
    local sigName=$(echo "${lines[-1]}" | jq '.[].critical.image."docker-manifest-digest"')
    [ "$status" -eq 0 ]
    [[ "$sigName" == *"${digest}"* ]]
}

@test "sign/verify with notation" {
    run curl -X POST -H "Content-Type: application/json" --data '{ "query": "{ ImageList(repo: \"annotations\") { Results { RepoName Tag Manifests {Digest ConfigDigest Size Layers { Size Digest }} Vendor Licenses }}}"}' http://localhost:8080/v2/_zot/ext/search
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.data.ImageList.Results[0].RepoName') = '"annotations"' ]
    [ "$status" -eq 0 ]

    run notation cert generate-test "notation-sign-test"
    [ "$status" -eq 0 ]

    local trust_policy_file=${HOME}/.config/notation/trustpolicy.json

    cat >${trust_policy_file} <<EOF
{
    "version": "1.0",
    "trustPolicies": [
        {
            "name": "notation-sign-test",
            "registryScopes": [ "*" ],
            "signatureVerification": {
                "level" : "strict" 
            },
            "trustStores": [ "ca:notation-sign-test" ],
            "trustedIdentities": [
                "*"
            ]
        }
    ]
}
EOF

    run notation sign --key "notation-sign-test" --plain-http localhost:8080/annotations:latest
    [ "$status" -eq 0 ]
    run notation verify --plain-http localhost:8080/annotations:latest
    [ "$status" -eq 0 ]
    run notation list --plain-http localhost:8080/annotations:latest
    [ "$status" -eq 0 ]
}
