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
    mkdir -p ${zot_root_dir}
    mkdir -p ${oci_data_dir}
    cat > ${zot_config_file}<<EOF
{
    "distSpecVersion": "1.0.1",
    "storage": {
        "rootDirectory": "${zot_root_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "8080"
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

@test "push image" {
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        oci:${TEST_DATA_DIR}/golang:1.18 \
        docker://127.0.0.1:8080/golang:1.18
    [ "$status" -eq 0 ]
    run curl http://127.0.0.1:8080/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories[]') = '"golang"' ]
    run curl http://127.0.0.1:8080/v2/golang/tags/list
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.tags[]') = '"1.18"' ]
}

@test "pull image" {
    local oci_data_dir=${BATS_FILE_TMPDIR}/oci
    run skopeo --insecure-policy copy --src-tls-verify=false \
        docker://127.0.0.1:8080/golang:1.18 \
        oci:${oci_data_dir}/golang:1.18
    [ "$status" -eq 0 ]
    run cat ${BATS_FILE_TMPDIR}/oci/golang/index.json
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.manifests[].annotations."org.opencontainers.image.ref.name"') = '"1.18"' ]
}

@test "push oras artifact" {
    echo "{\"name\":\"foo\",\"value\":\"bar\"}" > config.json
    echo "hello world" > artifact.txt
    run oras push --plain-http 127.0.0.1:8080/hello-artifact:v2 \
        --manifest-config config.json:application/vnd.acme.rocket.config.v1+json artifact.txt:text/plain -d -v
    [ "$status" -eq 0 ]
    rm -f artifact.txt
    rm -f config.json
}

@test "pull oras artifact" {
    run oras pull --plain-http 127.0.0.1:8080/hello-artifact:v2 -d -v
    [ "$status" -eq 0 ]
    grep -q "hello world" artifact.txt
    rm -f artifact.txt
}

@test "push helm chart" {
    run helm package ${BATS_FILE_TMPDIR}/helm-charts/charts/zot
    [ "$status" -eq 0 ]
    run helm push zot-0.1.0.tgz oci://localhost:8080/zot-chart
    [ "$status" -eq 0 ]
}

@test "pull helm chart" {
    run helm pull oci://localhost:8080/zot-chart/zot --version 0.1.0
    [ "$status" -eq 0 ]
}

@test "copy image with regclient" {
    run regctl registry set localhost:8080 --tls disabled
    [ "$status" -eq 0 ]
    run regctl image copy ocidir://${TEST_DATA_DIR}/golang:1.18 localhost:8080/test-regclient
    [ "$status" -eq 0 ]
}

@test "list all images with regclient" {
    run regctl repo ls localhost:8080
    [ "$status" -eq 0 ]

    found=0
    for i in "${lines[@]}"
    do

        if [ "$i" = 'test-regclient' ]; then
            found=1
        fi
    done
    [ "$found" -eq 1 ]
}

@test "list tags with regclient" {
    run regctl tag ls localhost:8080/test-regclient
    [ "$status" -eq 0 ]

    found=0
    for i in "${lines[@]}"
    do

        if [ "$i" = 'latest' ]; then
            found=1
        fi
    done
    [ "$found" -eq 1 ]
}

@test "get and push manifest with regclient" {
    manifest=$(regctl manifest get localhost:8080/test-regclient --format=raw-body)
    run regctl manifest put localhost:8080/test-regclient:1.0.0 --format oci --content-type application/vnd.oci.image.manifest.v1+json --format oci <<EOF
    $manifest
EOF
    [ "$status" -eq 0 ]
}

@test "get manifest with regclient" {
    run regctl manifest get localhost:8080/test-regclient
    [ "$status" -eq 0 ]
}

@test "pull image with regclient" {
    run regctl image copy localhost:8080/test-regclient ocidir://${TEST_DATA_DIR}/golang:1.18
    [ "$status" -eq 0 ]
}
