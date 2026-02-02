# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"
#       Makefile target installs & checks all necessary tooling
#       Extra tools that are not covered in Makefile target needs to be added in verify_prerequisites()

load helpers_zot
load helpers_upgrade
load ../port_helper

function setup_file() {
    # Use unique config name based on test file name and test run to avoid conflicts
    export REGISTRY_NAME=$(basename "${BASH_SOURCE[0]}" .bats)-$(basename "${BATS_FILE_TMPDIR}")
    # Verify prerequisites are available
    if ! $(verify_prerequisites); then
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
    zot_port=$(get_free_port_for_service "zot")
    echo ${zot_port} > ${BATS_FILE_TMPDIR}/zot.port
    cat > ${zot_config_file}<<JSON
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
        "output": "${BATS_FILE_TMPDIR}/zot.log"
    },
    "extensions": {
        "search": {
            "cve": {
                "updateInterval": "2h"
            }
        },
        "ui": {
            "enable": true
        }
    }
}
JSON
    git -C ${BATS_FILE_TMPDIR} clone https://github.com/project-zot/helm-charts.git
    zot_rel_serve ${zot_config_file}
    wait_zot_reachable ${zot_port}

    # setup zli to add zot registry to configs
    local registry_url="http://127.0.0.1:${zot_port}/"
    zli_add_config ${REGISTRY_NAME} ${registry_url}
}

# ==============================================================================
# RELEASE TESTS - Test released version before upgrade
# ==============================================================================

@test "[release] push image" {
    test_release_push_image
}

@test "[release] pull image" {
    test_release_pull_image
}

@test "[release] push image index" {
    test_release_push_image_index
}

@test "[release] pull image index" {
    test_release_pull_image_index
}

@test "[release] push oras artifact" {
    test_release_push_oras_artifact
}

@test "[release] pull oras artifact" {
    test_release_pull_oras_artifact
}

@test "[release] attach oras artifacts" {
    test_release_attach_oras_artifacts
}

@test "[release] discover oras artifacts" {
    test_release_discover_oras_artifacts
}

@test "[release] add and list tags using oras" {
    test_release_add_and_list_tags_using_oras
}

@test "[release] push helm chart" {
    test_release_push_helm_chart
}

@test "[release] pull helm chart" {
    test_release_pull_helm_chart
}

@test "[release] push image with regclient" {
    test_release_push_image_with_regclient
}

@test "[release] pull image with regclient" {
    test_release_pull_image_with_regclient
}

@test "[release] list repositories with regclient" {
    test_release_list_repositories_with_regclient
}

@test "[release] list image tags with regclient" {
    test_release_list_image_tags_with_regclient
}

@test "[release] push manifest with regclient" {
    test_release_push_manifest_with_regclient
}

@test "[release] pull manifest with regclient" {
    test_release_pull_manifest_with_regclient
}

@test "[release] pull manifest with docker client" {
    test_release_pull_manifest_with_docker_client
}

@test "[release] pull manifest with crictl" {
    test_release_pull_manifest_with_crictl
}

@test "[release] push OCI artifact with regclient" {
    test_release_push_oci_artifact_with_regclient
}

@test "[release] pull OCI artifact with regclient" {
    test_release_pull_oci_artifact_with_regclient
}

@test "[release] push OCI artifact references with regclient" {
    test_release_push_oci_artifact_references_with_regclient
}

@test "[release] pull OCI artifact references with regclient" {
    test_release_pull_oci_artifact_references_with_regclient
}

@test "[release] push docker image" {
    test_release_push_docker_image
}

@test "[release] list by image name" {
    zot_port=$(get_zot_port)
    run ${ZLI_PATH} repo list --config ${REGISTRY_NAME}
    [ "$status" -eq 0 ]

    echo ${lines[@]}
}

@test "[release] cve by image name and tag" {
    zot_port=$(get_zot_port)
    run ${ZLI_PATH} cve list golang:1.20 --config ${REGISTRY_NAME}
    [ "$status" -eq 0 ]

    echo ${lines[@]}

    found=0
    for i in "${lines[@]}"
    do
        if [[ "$i" = *"CVE-2011-4915    LOW      fs/proc/base.c in the Linux kernel through 3..."* ]]; then
            found=1
        fi
    done
    [ "$found" -eq 1 ]
}

# ==============================================================================
# UPGRADE - Switch to new binary
# ==============================================================================

@test "[upgrade] upgrade to new binary" {
    zot_stop_all
    local zot_config_file=${BATS_FILE_TMPDIR}/zot_config.json
    local zot_port=$(get_zot_port)
    zot_serve ${ZOT_PATH} ${zot_config_file}
    wait_zot_reachable ${zot_port}
    sleep 60    # zot does additional initialization/verification during startup
}

# ==============================================================================
# NEW TESTS - Test new version after upgrade
# After upgrading to the new binary, expect additional artifacts (a signature
# and an sbom) that were attached
# ==============================================================================

@test "[new] existing list by image name" {
    zot_port=$(get_zot_port)
    run ${ZLI_PATH} repo list --config ${REGISTRY_NAME}
    [ "$status" -eq 0 ]

    echo ${lines[@]}
    found=0
    for i in "${lines[@]}"
    do
        case "$i" in 
            busybox | golang)
                ((++found))
                ;;
            *)
                ;;
        esac
    done
    [ "$found" -eq 2 ]
}

@test "[new] existing cve by image name and tag" {
    zot_port=$(get_zot_port)
    run ${ZLI_PATH} cve list golang:1.20 --config ${REGISTRY_NAME}
    [ "$status" -eq 0 ]

    echo ${lines[@]}

    found=0
    for i in "${lines[@]}"
    do
        if [[ "$i" = *"CVE-2011-4915    LOW      fs/proc/base.c in the Linux kernel through 3..."* ]]; then
            found=1
        fi
    done
    [ "$found" -eq 1 ]
}

@test "[new] existing pull image" {
    test_new_existing_pull_image
}

@test "[new] existing pull image index" {
    test_new_existing_pull_image_index
}

@test "[new] existing pull oras artifact" {
    test_new_existing_pull_oras_artifact
}

@test "[new] existing list repositories with regclient" {
    zot_port=$(get_zot_port)
    run regctl repo ls localhost:${zot_port}
    [ "$status" -eq 0 ]

    found=0
    for i in "${lines[@]}"
    do
        if [ "$i" = 'test-regclient' ]; then
            found=1
        fi
    done
    [ "$found" -eq 1 ]

    run regctl repo ls --limit 4 localhost:${zot_port}
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 4 ]
    [ "${lines[-2]}" == "busybox" ]
    [ "${lines[-1]}" == "golang" ]

    run regctl repo ls --last busybox --limit 1 localhost:${zot_port}
    [ "$status" -eq 0 ]
    echo "$output"
    [ $(echo "$output" | wc -l) -eq 1 ]
    [ "${lines[-1]}" == "golang" ]
}

@test "[new] push image" {
    test_new_push_image
}

@test "[new] pull image" {
    test_new_pull_image
}

@test "[new] push image index" {
    test_new_push_image_index
}

@test "[new] pull image index" {
    test_new_pull_image_index
}

@test "[new] push oras artifact" {
    test_new_push_oras_artifact
}

@test "[new] pull oras artifact" {
    test_new_pull_oras_artifact
}

@test "[new] attach oras artifacts" {
    test_new_attach_oras_artifacts
}

@test "[new] discover oras artifacts" {
    test_new_discover_oras_artifacts 4
}

@test "[new] add and list tags using oras" {
    test_new_add_and_list_tags_using_oras
}

@test "[new] push helm chart" {
    test_new_push_helm_chart
}

@test "[new] pull helm chart" {
    test_new_pull_helm_chart
}

@test "[new] push image with regclient" {
    test_new_push_image_with_regclient
}

@test "[new] pull image with regclient" {
    test_new_pull_image_with_regclient
}

@test "[new] list repositories with regclient" {
    test_new_list_repositories_with_regclient
}

@test "[new] list image tags with regclient" {
    test_new_list_image_tags_with_regclient
}

@test "[new] push manifest with regclient" {
    test_new_push_manifest_with_regclient
}

@test "[new] pull manifest with regclient" {
    test_new_pull_manifest_with_regclient
}

@test "[new] pull manifest with docker client" {
    test_new_pull_manifest_with_docker_client
}

@test "[new] pull manifest with crictl" {
    test_new_pull_manifest_with_crictl
}

@test "[new] push OCI artifact with regclient" {
    test_new_push_oci_artifact_with_regclient
}

@test "[new] pull OCI artifact with regclient" {
    test_new_pull_oci_artifact_with_regclient
}

@test "[new] push OCI artifact references with regclient" {
    test_new_push_oci_artifact_references_with_regclient
}

@test "[new] pull OCI artifact references with regclient" {
    test_new_pull_oci_artifact_references_with_regclient
}

@test "[new] push docker image" {
    test_new_push_docker_image
}

@test "[new] list by image name" {
    zot_port=$(get_zot_port)
    run ${ZLI_PATH} repo list --config ${REGISTRY_NAME}
    [ "$status" -eq 0 ]

    echo ${lines[@]}
    found=0
    for i in "${lines[@]}"
    do
        case "$i" in 
            alpine | busybox | golang)
                ((++found))
                ;;
            *)
                ;;
        esac
    done
    [ "$found" -eq 3 ]
}

@test "[new] cve by image name and tag" {
    zot_port=$(get_zot_port)
    run ${ZLI_PATH} cve list golang:1.20 --config ${REGISTRY_NAME}
    [ "$status" -eq 0 ]

    echo ${lines[@]}

    found=0
    for i in "${lines[@]}"
    do
        if [[ "$i" = *"CVE-2011-4915    LOW      fs/proc/base.c in the Linux kernel through 3..."* ]]; then
            found=1
        fi
    done
    [ "$found" -eq 1 ]

    run ${ZLI_PATH} cve list alpine:3.17.3 --config ${REGISTRY_NAME}
    [ "$status" -eq 0 ]

    echo ${lines[@]}

    found=0
    for i in "${lines[@]}"
    do
        if [[ "$i" = *"CVE-2025-26519   UNKNOWN  musl libc 0.9.13 through 1.2.5 before 1.2.6 h..."* ]]; then
            found=1
        fi
    done
    [ "$found" -eq 1 ]
}
