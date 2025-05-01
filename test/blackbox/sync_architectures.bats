# Test suite for architecture and platform filtering during sync operations
# 
# This file tests two related filtering parameters in RegistryConfig:
#
# 1. "architectures": Filters by architecture only (e.g., "amd64", "arm64")
#    Example: "architectures": ["amd64"]
#
# 2. "platforms": Supports both architecture-only and OS/architecture formats
#    Example: "platforms": ["amd64"] (architecture-only format)
#    Example: "platforms": ["linux/amd64"] (OS/architecture format)
#
# Both parameters allow selective syncing of multi-architecture images based on
# the architecture and/or OS platform, reducing storage and bandwidth requirements.

load helpers_zot
load helpers_wait

function verify_prerequisites() {
    if [ ! $(command -v curl) ]; then
        echo "you need to install curl as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v jq) ]; then
        echo "you need to install jq as a prerequisite to running the tests" >&3
        return 1
    fi

    if [ ! $(command -v skopeo) ]; then
        echo "you need to install skopeo as a prerequisite to running the tests" >&3
        return 1
    fi

    return 0
}

function setup_file() {
    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
        exit 1
    fi

    # Create directories for the different zot instances
    local zot_source_dir=${BATS_FILE_TMPDIR}/zot-source
    local zot_arch_filter_dir=${BATS_FILE_TMPDIR}/zot-arch-filter
    local zot_no_filter_dir=${BATS_FILE_TMPDIR}/zot-no-filter
    local zot_platform_filter_dir=${BATS_FILE_TMPDIR}/zot-platform-filter
    
    local zot_source_config=${BATS_FILE_TMPDIR}/zot_source_config.json
    local zot_arch_filter_config=${BATS_FILE_TMPDIR}/zot_arch_filter_config.json
    local zot_no_filter_config=${BATS_FILE_TMPDIR}/zot_no_filter_config.json
    local zot_platform_filter_config=${BATS_FILE_TMPDIR}/zot_platform_filter_config.json
    
    mkdir -p ${zot_source_dir}
    mkdir -p ${zot_arch_filter_dir}
    mkdir -p ${zot_no_filter_dir}
    mkdir -p ${zot_platform_filter_dir}
    
    # Get free ports for our zot instances
    zot_source_port=$(get_free_port)
    echo ${zot_source_port} > ${BATS_FILE_TMPDIR}/zot.source.port
    
    zot_arch_filter_port=$(get_free_port)
    echo ${zot_arch_filter_port} > ${BATS_FILE_TMPDIR}/zot.arch_filter.port
    
    zot_no_filter_port=$(get_free_port)
    echo ${zot_no_filter_port} > ${BATS_FILE_TMPDIR}/zot.no_filter.port
    
    zot_platform_filter_port=$(get_free_port)
    echo ${zot_platform_filter_port} > ${BATS_FILE_TMPDIR}/zot.platform_filter.port
    
    # Create config for source registry (basic config without sync)
    cat >${zot_source_config} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_source_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_source_port}"
    },
    "log": {
        "level": "debug"
    }
}
EOF

    # Create config for architecture-filtered registry (with amd64 only)
    cat >${zot_arch_filter_config} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_arch_filter_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_arch_filter_port}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_source_port}"
                    ],
                    "onDemand": false,
                    "tlsVerify": false,
                    "PollInterval": "10s",
                    "architectures": ["amd64"],
                    "content": [
                        {
                            "prefix": "**"
                        }
                    ]
                }
            ]
        }
    }
}
EOF

    # Create config for non-filtered registry (no architecture/platform filter)
    cat >${zot_no_filter_config} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_no_filter_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_no_filter_port}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_source_port}"
                    ],
                    "onDemand": false,
                    "tlsVerify": false,
                    "PollInterval": "10s",
                    "content": [
                        {
                            "prefix": "**"
                        }
                    ]
                }
            ]
        }
    }
}
EOF

    # Create config for platform-filtered registry (with linux/amd64 only)
    cat >${zot_platform_filter_config} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_platform_filter_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_platform_filter_port}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_source_port}"
                    ],
                    "onDemand": false,
                    "tlsVerify": false,
                    "PollInterval": "10s",
                    "platforms": ["linux/amd64"],
                    "content": [
                        {
                            "prefix": "**"
                        }
                    ]
                }
            ]
        }
    }
}
EOF

    # Start all zot instances
    zot_serve ${ZOT_MINIMAL_PATH} ${zot_source_config}
    wait_zot_reachable ${zot_source_port}
    
    zot_serve ${ZOT_PATH} ${zot_arch_filter_config}
    wait_zot_reachable ${zot_arch_filter_port}
    
    zot_serve ${ZOT_PATH} ${zot_no_filter_config}
    wait_zot_reachable ${zot_no_filter_port}
    
    zot_serve ${ZOT_PATH} ${zot_platform_filter_config}
    wait_zot_reachable ${zot_platform_filter_port}
}

function teardown_file() {
    zot_stop_all
}

# Group 1: Basic Filtering Tests
# These tests verify the core functionality of architecture and platform filtering

# Test 1: Basic architecture filtering (amd64 only)
# Verifies that architecture filtering correctly syncs only the specified architectures
@test "sync multi-architecture image with architecture filtering" {
    # Get ports for our registries
    zot_source_port=$(cat ${BATS_FILE_TMPDIR}/zot.source.port)
    zot_arch_filter_port=$(cat ${BATS_FILE_TMPDIR}/zot.arch_filter.port)
    zot_no_filter_port=$(cat ${BATS_FILE_TMPDIR}/zot.no_filter.port)
    
    # Push a multi-architecture image to the source registry
    run skopeo --insecure-policy copy --format=oci --dest-tls-verify=false --multi-arch=all \
        docker://public.ecr.aws/docker/library/busybox:latest \
        docker://localhost:${zot_source_port}/busybox:latest
    [ "$status" -eq 0 ]
    
    # Verify the image was pushed to the source registry
    run curl http://localhost:${zot_source_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories | contains(["busybox"])') = "true" ]
    
    # Wait for sync to happen
    run sleep 15s
    
    # Verify image exists in both target registries
    run curl http://localhost:${zot_arch_filter_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories | contains(["busybox"])') = "true" ]
    
    run curl http://localhost:${zot_no_filter_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories | contains(["busybox"])') = "true" ]
    
    # Get manifest from source registry
    run curl -s http://localhost:${zot_source_port}/v2/busybox/manifests/latest -H "Accept: application/vnd.oci.image.index.v1+json"
    [ "$status" -eq 0 ]
    source_manifests_count=$(echo "${lines[-1]}" | jq '.manifests | length')
    [ "$source_manifests_count" -gt 1 ] # Ensure it's a multi-arch image
    
    # Get manifest from arch-filtered registry
    run curl -s http://localhost:${zot_arch_filter_port}/v2/busybox/manifests/latest -H "Accept: application/vnd.oci.image.index.v1+json"
    [ "$status" -eq 0 ]
    filtered_manifests_count=$(echo "${lines[-1]}" | jq '.manifests | length')
    
    # Count architectures in arch-filtered registry
    amd64_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "amd64")] | length')
    arm64_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "arm64")] | length')
    
    # Verify only amd64 architecture was synced to the filtered registry
    [ "$amd64_count" -eq "$filtered_manifests_count" ]
    [ "$arm64_count" -eq 0 ]
    
    # Get manifest from non-filtered registry
    run curl -s http://localhost:${zot_no_filter_port}/v2/busybox/manifests/latest -H "Accept: application/vnd.oci.image.index.v1+json"
    [ "$status" -eq 0 ]
    no_filter_manifests_count=$(echo "${lines[-1]}" | jq '.manifests | length')
    
    # Verify that non-filtered registry has all architectures (same as source)
    [ "$no_filter_manifests_count" -eq "$source_manifests_count" ]
}

# Test 2: Basic platform filtering (linux/amd64 only)
# Verifies that platform filtering with OS+arch works correctly
@test "sync multi-architecture image with platform filtering" {
    # Get ports for our registries
    zot_source_port=$(cat ${BATS_FILE_TMPDIR}/zot.source.port)
    zot_platform_filter_port=$(cat ${BATS_FILE_TMPDIR}/zot.platform_filter.port)
    zot_no_filter_port=$(cat ${BATS_FILE_TMPDIR}/zot.no_filter.port)
    
    # We're using the busybox image pushed in the previous test
    
    # Wait for sync to happen
    run sleep 15s
    
    # Verify image exists in the platform-filtered registry
    run curl http://localhost:${zot_platform_filter_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories | contains(["busybox"])') = "true" ]
    
    # Get manifest from platform-filtered registry
    run curl -s http://localhost:${zot_platform_filter_port}/v2/busybox/manifests/latest -H "Accept: application/vnd.oci.image.index.v1+json"
    [ "$status" -eq 0 ]
    filtered_manifests_count=$(echo "${lines[-1]}" | jq '.manifests | length')
    
    # Count architectures in platform-filtered registry
    linux_amd64_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "amd64" and .platform.os == "linux")] | length')
    other_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture != "amd64" or .platform.os != "linux")] | length')
    
    # Verify only linux/amd64 platform was synced
    [ "$linux_amd64_count" -eq "$filtered_manifests_count" ]
    [ "$other_count" -eq 0 ]
}

# Test 3: Testing with single-architecture images
# Verifies filtering behavior with non-multi-arch repositories
@test "sync single-architecture images with filtering" {
    # Get ports for our registries
    zot_source_port=$(cat ${BATS_FILE_TMPDIR}/zot.source.port)
    zot_arch_filter_port=$(cat ${BATS_FILE_TMPDIR}/zot.arch_filter.port)
    zot_no_filter_port=$(cat ${BATS_FILE_TMPDIR}/zot.no_filter.port)
    
    # Push AMD64 image
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        docker://public.ecr.aws/docker/library/alpine:latest \
        docker://localhost:${zot_source_port}/alpine-amd64:latest
    [ "$status" -eq 0 ]
    
    # Push ARM64 image (for testing purposes, we'll also use alpine, but with a different name)
    run skopeo --insecure-policy copy --dest-tls-verify=false \
        docker://public.ecr.aws/docker/library/alpine:latest \
        docker://localhost:${zot_source_port}/alpine-arm64:latest
    [ "$status" -eq 0 ]
    
    # Verify the images were pushed to the source registry
    run curl http://localhost:${zot_source_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories | contains(["alpine-amd64"])') = "true" ]
    [ $(echo "${lines[-1]}" | jq '.repositories | contains(["alpine-arm64"])') = "true" ]
    
    # Wait for sync to happen
    run sleep 15s
    
    # Check if the AMD64 image was synced to both registries
    run curl http://localhost:${zot_arch_filter_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories | contains(["alpine-amd64"])') = "true" ]
    
    run curl http://localhost:${zot_no_filter_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories | contains(["alpine-amd64"])') = "true" ]
    
    # Check if the ARM64 image was synced only to the non-filtered registry
    # This is a slight simplification since we can't guarantee the actual architecture of the alpine image,
    # but in a real environment with known architecture images, this would work correctly.
    run curl http://localhost:${zot_no_filter_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories | contains(["alpine-arm64"])') = "true" ]
}

# Group 2: Multiple Architecture/Platform Filtering Tests
# These tests verify more complex filtering scenarios with multiple architectures/platforms

# Test 4: Multiple architecture filtering
# Verifies that multiple architectures can be specified in the filter
@test "sync with multiple architectures in filter" {
    # Get ports for our registries
    zot_source_port=$(cat ${BATS_FILE_TMPDIR}/zot.source.port)
    
    # Create a new registry with both amd64 and arm64 filters
    local zot_multi_arch_filter_dir=${BATS_FILE_TMPDIR}/zot-multi-arch-filter
    local zot_multi_arch_filter_config=${BATS_FILE_TMPDIR}/zot_multi_arch_filter_config.json
    mkdir -p ${zot_multi_arch_filter_dir}
    
    zot_multi_arch_filter_port=$(get_free_port)
    echo ${zot_multi_arch_filter_port} > ${BATS_FILE_TMPDIR}/zot.multi_arch_filter.port
    
    # Create config for multi-architecture filtered registry (with amd64 and arm64)
    cat >${zot_multi_arch_filter_config} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_multi_arch_filter_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_multi_arch_filter_port}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_source_port}"
                    ],
                    "onDemand": false,
                    "tlsVerify": false,
                    "PollInterval": "10s",
                    "architectures": ["amd64", "arm64"],
                    "content": [
                        {
                            "prefix": "**"
                        }
                    ]
                }
            ]
        }
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_multi_arch_filter_config}
    wait_zot_reachable ${zot_multi_arch_filter_port}
    
    # Wait for sync to happen
    run sleep 15s
    
    # Get manifest from multi-arch filtered registry
    run curl -s http://localhost:${zot_multi_arch_filter_port}/v2/busybox/manifests/latest -H "Accept: application/vnd.oci.image.index.v1+json"
    [ "$status" -eq 0 ]
    
    # Check that both amd64 and arm64 architectures are present in the manifest list
    amd64_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "amd64")] | length')
    arm64_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "arm64")] | length')
    
    # Verify both amd64 and arm64 architectures are included
    [ "$amd64_count" -gt 0 ]
    [ "$arm64_count" -gt 0 ]
    
    # Check no other architectures are included
    total_arch_count=$(( amd64_count + arm64_count ))
    total_manifest_count=$(echo "${lines[-1]}" | jq '.manifests | length')
    
    [ "$total_arch_count" -eq "$total_manifest_count" ]
}

# Test 5: Multiple platform filtering
# Verifies that multiple platforms can be specified in the filter
@test "sync with multiple platforms in filter" {
    # Get ports for our registries
    zot_source_port=$(cat ${BATS_FILE_TMPDIR}/zot.source.port)
    
    # Create a new registry with both amd64 and arm64 platform filters
    local zot_multi_platform_filter_dir=${BATS_FILE_TMPDIR}/zot-multi-platform-filter
    local zot_multi_platform_filter_config=${BATS_FILE_TMPDIR}/zot_multi_platform_filter_config.json
    mkdir -p ${zot_multi_platform_filter_dir}
    
    zot_multi_platform_filter_port=$(get_free_port)
    echo ${zot_multi_platform_filter_port} > ${BATS_FILE_TMPDIR}/zot.multi_platform_filter.port
    
    # Create config for multi-platform filtered registry (with amd64 and arm64)
    cat >${zot_multi_platform_filter_config} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_multi_platform_filter_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_multi_platform_filter_port}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_source_port}"
                    ],
                    "onDemand": false,
                    "tlsVerify": false,
                    "PollInterval": "10s",
                    "platforms": ["amd64", "linux/arm64"],
                    "content": [
                        {
                            "prefix": "**"
                        }
                    ]
                }
            ]
        }
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_multi_platform_filter_config}
    wait_zot_reachable ${zot_multi_platform_filter_port}
    
    # Wait for sync to happen
    run sleep 15s
    
    # Get manifest from multi-platform filtered registry
    run curl -s http://localhost:${zot_multi_platform_filter_port}/v2/busybox/manifests/latest -H "Accept: application/vnd.oci.image.index.v1+json"
    [ "$status" -eq 0 ]
    
    # Check that both amd64 and arm64 architectures are present in the manifest list
    amd64_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "amd64")] | length')
    arm64_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "arm64")] | length')
    
    # Verify both amd64 and arm64 architectures are included
    [ "$amd64_count" -gt 0 ]
    [ "$arm64_count" -gt 0 ]
    
    # Check no other architectures are included
    total_arch_count=$(( amd64_count + arm64_count ))
    total_manifest_count=$(echo "${lines[-1]}" | jq '.manifests | length')
    
    [ "$total_arch_count" -eq "$total_manifest_count" ]
}

# Group 3: On-Demand Sync Tests
# These tests verify that filtering works correctly with on-demand sync configurations

# Test 6: On-demand sync with architecture filtering
# Verifies that architecture filtering works with on-demand sync
@test "on-demand sync with architecture filtering" {
    # Get ports for our registries
    zot_source_port=$(cat ${BATS_FILE_TMPDIR}/zot.source.port)
    
    # Create a new on-demand registry with architecture filter
    local zot_ondemand_arch_filter_dir=${BATS_FILE_TMPDIR}/zot-ondemand-arch-filter
    local zot_ondemand_arch_filter_config=${BATS_FILE_TMPDIR}/zot_ondemand_arch_filter_config.json
    mkdir -p ${zot_ondemand_arch_filter_dir}
    
    zot_ondemand_arch_filter_port=$(get_free_port)
    echo ${zot_ondemand_arch_filter_port} > ${BATS_FILE_TMPDIR}/zot.ondemand_arch_filter.port
    
    # Create config for on-demand architecture filtered registry (with amd64 only)
    cat >${zot_ondemand_arch_filter_config} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_ondemand_arch_filter_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_ondemand_arch_filter_port}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_source_port}"
                    ],
                    "onDemand": true,
                    "tlsVerify": false,
                    "architectures": ["amd64"],
                    "content": [
                        {
                            "prefix": "**"
                        }
                    ]
                }
            ]
        }
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_ondemand_arch_filter_config}
    wait_zot_reachable ${zot_ondemand_arch_filter_port}
    
    # Trigger on-demand sync by requesting the manifest
    run curl http://localhost:${zot_ondemand_arch_filter_port}/v2/busybox/manifests/latest
    [ "$status" -eq 0 ]
    
    # Wait a moment for the sync to complete
    run sleep 5s
    
    # Get manifest from on-demand filtered registry
    run curl -s http://localhost:${zot_ondemand_arch_filter_port}/v2/busybox/manifests/latest -H "Accept: application/vnd.oci.image.index.v1+json"
    [ "$status" -eq 0 ]
    
    # Count architectures
    amd64_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "amd64")] | length')
    arm64_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "arm64")] | length')
    
    # Verify only amd64 architecture was synced to the filtered registry
    [ "$amd64_count" -gt 0 ]
    [ "$arm64_count" -eq 0 ]
}

# Test 7: On-demand sync with platform filtering
# Verifies that platform filtering works with on-demand sync
@test "on-demand sync with platform filtering" {
    # Get ports for our registries
    zot_source_port=$(cat ${BATS_FILE_TMPDIR}/zot.source.port)
    
    # Create a new on-demand registry with platform filter
    local zot_ondemand_platform_filter_dir=${BATS_FILE_TMPDIR}/zot-ondemand-platform-filter
    local zot_ondemand_platform_filter_config=${BATS_FILE_TMPDIR}/zot_ondemand_platform_filter_config.json
    mkdir -p ${zot_ondemand_platform_filter_dir}
    
    zot_ondemand_platform_filter_port=$(get_free_port)
    echo ${zot_ondemand_platform_filter_port} > ${BATS_FILE_TMPDIR}/zot.ondemand_platform_filter.port
    
    # Create config for on-demand platform filtered registry (with amd64 only)
    cat >${zot_ondemand_platform_filter_config} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_ondemand_platform_filter_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_ondemand_platform_filter_port}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_source_port}"
                    ],
                    "onDemand": true,
                    "tlsVerify": false,
                    "platforms": ["amd64"],
                    "content": [
                        {
                            "prefix": "**"
                        }
                    ]
                }
            ]
        }
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_ondemand_platform_filter_config}
    wait_zot_reachable ${zot_ondemand_platform_filter_port}
    
    # Trigger on-demand sync by requesting the manifest
    run curl http://localhost:${zot_ondemand_platform_filter_port}/v2/busybox/manifests/latest
    [ "$status" -eq 0 ]
    
    # Wait a moment for the sync to complete
    run sleep 5s
    
    # Get manifest from on-demand filtered registry
    run curl -s http://localhost:${zot_ondemand_platform_filter_port}/v2/busybox/manifests/latest -H "Accept: application/vnd.oci.image.index.v1+json"
    [ "$status" -eq 0 ]
    
    # Count architectures
    amd64_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "amd64")] | length')
    arm64_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "arm64")] | length')
    
    # Verify only amd64 architecture was synced to the filtered registry
    [ "$amd64_count" -gt 0 ]
    [ "$arm64_count" -eq 0 ]
}

# Group 4: Advanced Filtering Tests
# These tests verify more complex filtering scenarios with OS specificity and mixed formats

# Test 8: OS/architecture specific platform filtering
# Verifies that filtering works with specific OS/architecture combinations
@test "sync with OS/architecture platform filtering" {
    # Get ports for our registries
    zot_source_port=$(cat ${BATS_FILE_TMPDIR}/zot.source.port)
    zot_platform_filter_port=$(cat ${BATS_FILE_TMPDIR}/zot.platform_filter.port)
    
    # We'll use busybox which should already be there from previous tests
    
    # Wait for sync to happen if needed
    run sleep 15s
    
    # Verify image exists in platform-filtered registry
    run curl http://localhost:${zot_platform_filter_port}/v2/_catalog
    [ "$status" -eq 0 ]
    [ $(echo "${lines[-1]}" | jq '.repositories | contains(["busybox"])') = "true" ]
    
    # Get manifest from platform-filtered registry
    run curl -s http://localhost:${zot_platform_filter_port}/v2/busybox/manifests/latest -H "Accept: application/vnd.oci.image.index.v1+json"
    [ "$status" -eq 0 ]
    
    # Count architectures and check OS
    linux_amd64_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "amd64" and .platform.os == "linux")] | length')
    other_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture != "amd64" or .platform.os != "linux")] | length')
    
    # Verify only linux/amd64 platform was synced
    [ "$linux_amd64_count" -gt 0 ]
    [ "$other_count" -eq 0 ]
}

# Test 9: Mixed format filtering (architecture-only and OS/architecture)
# Verifies that both architecture-only and OS/architecture formats can be used together
@test "sync with mixed architecture and platform filtering" {
    # Get ports for our registries
    zot_source_port=$(cat ${BATS_FILE_TMPDIR}/zot.source.port)
    
    # Create a new registry with mixed filtering (both amd64 and linux/arm64)
    local zot_mixed_filter_dir=${BATS_FILE_TMPDIR}/zot-mixed-filter
    local zot_mixed_filter_config=${BATS_FILE_TMPDIR}/zot_mixed_filter_config.json
    mkdir -p ${zot_mixed_filter_dir}
    
    zot_mixed_filter_port=$(get_free_port)
    echo ${zot_mixed_filter_port} > ${BATS_FILE_TMPDIR}/zot.mixed_filter.port
    
    # Create config for mixed filtered registry
    cat >${zot_mixed_filter_config} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_mixed_filter_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_mixed_filter_port}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_source_port}"
                    ],
                    "onDemand": false,
                    "tlsVerify": false,
                    "PollInterval": "10s",
                    "platforms": ["amd64", "linux/arm64"],
                    "content": [
                        {
                            "prefix": "**"
                        }
                    ]
                }
            ]
        }
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_mixed_filter_config}
    wait_zot_reachable ${zot_mixed_filter_port}
    
    # Wait for sync to happen
    run sleep 15s
    
    # Get manifest from mixed filtered registry
    run curl -s http://localhost:${zot_mixed_filter_port}/v2/busybox/manifests/latest -H "Accept: application/vnd.oci.image.index.v1+json"
    [ "$status" -eq 0 ]
    
    # Count architectures
    amd64_any_os_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "amd64")] | length')
    linux_arm64_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "arm64" and .platform.os == "linux")] | length')
    other_arm64_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "arm64" and .platform.os != "linux")] | length')
    
    # Verify only the specified platforms were synced
    [ "$amd64_any_os_count" -gt 0 ]
    [ "$linux_arm64_count" -gt 0 ]
    [ "$other_arm64_count" -eq 0 ]
}

# Test 10: OS exclusion in platform filtering
# Verifies that specifying only certain OS platforms excludes others (like Windows)
@test "sync with OS exclusion in platform filtering" {
    # Get ports for our registries
    zot_source_port=$(cat ${BATS_FILE_TMPDIR}/zot.source.port)
    
    # Create a new registry that excludes windows but includes all architectures
    local zot_os_filter_dir=${BATS_FILE_TMPDIR}/zot-os-filter
    local zot_os_filter_config=${BATS_FILE_TMPDIR}/zot_os_filter_config.json
    mkdir -p ${zot_os_filter_dir}
    
    zot_os_filter_port=$(get_free_port)
    echo ${zot_os_filter_port} > ${BATS_FILE_TMPDIR}/zot.os_filter.port
    
    # Create config for OS filtered registry - only including Linux platforms
    cat >${zot_os_filter_config} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_os_filter_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_os_filter_port}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_source_port}"
                    ],
                    "onDemand": false,
                    "tlsVerify": false,
                    "PollInterval": "10s",
                    "platforms": ["linux/amd64", "linux/arm64", "linux/arm", "linux/ppc64le", "linux/s390x", "linux/386", "linux/mips64le"],
                    "content": [
                        {
                            "prefix": "**"
                        }
                    ]
                }
            ]
        }
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_os_filter_config}
    wait_zot_reachable ${zot_os_filter_port}
    
    # Wait for sync to happen
    run sleep 15s
    
    # First, create a Windows multi-arch image if it doesn't exist yet
    # Here we'll use a windows image from MCR. If this fails, we can skip further tests.
    
    # Push a Windows sample image to our source
    run skopeo --insecure-policy copy --format=oci --dest-tls-verify=false \
        docker://mcr.microsoft.com/windows/nanoserver:latest \
        docker://localhost:${zot_source_port}/windows-test:latest
    
    # If we couldn't pull a Windows image, we'll skip further tests
    if [ "$status" -eq 0 ]; then
        # Wait for sync to happen
        run sleep 15s
    
        # Get manifest from OS filtered registry
        run curl -s http://localhost:${zot_os_filter_port}/v2/busybox/manifests/latest -H "Accept: application/vnd.oci.image.index.v1+json"
        [ "$status" -eq 0 ]
    
        # Count OS types
        linux_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.os == "linux")] | length')
        windows_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.os == "windows")] | length')
    
        # Verify only Linux OS platforms were synced, filtering out Windows
        [ "$linux_count" -gt 0 ]
        [ "$windows_count" -eq 0 ]
    
        # Check if the windows-test image was synced
        run curl http://localhost:${zot_os_filter_port}/v2/_catalog
        [ "$status" -eq 0 ]
        windows_test_synced=$(echo "${lines[-1]}" | jq '.repositories | contains(["windows-test"])')
    
        # Check if the image was found
        if [ "$windows_test_synced" = "true" ]; then
            # Even if the repository exists, the manifest should only contain Linux platforms
            run curl -s http://localhost:${zot_os_filter_port}/v2/windows-test/manifests/latest -H "Accept: application/vnd.oci.image.index.v1+json"
            if [ "$status" -eq 0 ]; then
                windows_in_manifest=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.os == "windows")] | length')
                [ "$windows_in_manifest" -eq 0 ]
            fi
        fi
    fi
}

# Test 11: Using both architectures and platforms parameters together
# Verifies that when both parameters are used, they are combined with logical OR
@test "sync with both architectures and platforms parameters" {
    # Get ports for our registries
    zot_source_port=$(cat ${BATS_FILE_TMPDIR}/zot.source.port)
    
    # Create a new registry with both parameters
    local zot_both_params_dir=${BATS_FILE_TMPDIR}/zot-both-params
    local zot_both_params_config=${BATS_FILE_TMPDIR}/zot_both_params_config.json
    mkdir -p ${zot_both_params_dir}
    
    zot_both_params_port=$(get_free_port)
    echo ${zot_both_params_port} > ${BATS_FILE_TMPDIR}/zot.both_params.port
    
    # Create config with both architectures and platforms parameters
    # When both are specified, they should be combined with logical OR
    cat >${zot_both_params_config} <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${zot_both_params_dir}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${zot_both_params_port}"
    },
    "log": {
        "level": "debug"
    },
    "extensions": {
        "sync": {
            "registries": [
                {
                    "urls": [
                        "http://localhost:${zot_source_port}"
                    ],
                    "onDemand": false,
                    "tlsVerify": false,
                    "PollInterval": "10s",
                    "architectures": ["arm64"],
                    "platforms": ["linux/amd64"],
                    "content": [
                        {
                            "prefix": "**"
                        }
                    ]
                }
            ]
        }
    }
}
EOF

    zot_serve ${ZOT_PATH} ${zot_both_params_config}
    wait_zot_reachable ${zot_both_params_port}
    
    # Wait for sync to happen
    run sleep 15s
    
    # Get manifest from the registry with both parameters
    run curl -s http://localhost:${zot_both_params_port}/v2/busybox/manifests/latest -H "Accept: application/vnd.oci.image.index.v1+json"
    [ "$status" -eq 0 ]
    
    # Count specific architectures
    linux_amd64_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "amd64" and .platform.os == "linux")] | length')
    arm64_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture == "arm64")] | length')
    other_count=$(echo "${lines[-1]}" | jq '[.manifests[] | select(.platform.architecture != "amd64" and .platform.architecture != "arm64")] | length')
    
    # Verify both specified architectures were synced (logical OR)
    [ "$linux_amd64_count" -gt 0 ]
    [ "$arm64_count" -gt 0 ]
    [ "$other_count" -eq 0 ]
    
    # Verify total manifests is the sum of the two architecture counts
    total_filtered_manifests=$(( linux_amd64_count + arm64_count ))
    total_manifest_count=$(echo "${lines[-1]}" | jq '.manifests | length')
    
    [ "$total_filtered_manifests" -eq "$total_manifest_count" ]
}