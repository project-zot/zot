# Note: Intended to be run as "make run-blackbox-tests" or "make run-blackbox-ci"

# This test suite verifies that zot's streaming on-demand sync works correctly
# when kubelet pulls images through zot.

load helpers_zot
load helpers_wait
load ../port_helper

KIND="${ROOT_DIR}/hack/tools/bin/kind"
CLUSTER_NAME="zotstream"

function verify_prerequisites() {
    local ok=0
    for cmd in curl jq docker kubectl; do
        if ! command -v "${cmd}" &>/dev/null; then
            echo "you need to install ${cmd} as a prerequisite to running the tests" >&3
            ok=1
        fi
    done

    if [ ! -f "${KIND}" ]; then
        echo "kind not found at ${KIND}; run 'make check-blackbox-prerequisites' first" >&3
        ok=1
    fi

    return "${ok}"
}

function setup_file() {
    if ! verify_prerequisites; then
        exit 1
    fi

    local test_root="${BATS_FILE_TMPDIR}/zot-test"
    mkdir -p "${test_root}"

    echo "${test_root}" > "${BATS_FILE_TMPDIR}/test_root"

    local test_port
    test_port=$(get_free_port_for_service "zot_test")
    echo "${test_port}" > "${BATS_FILE_TMPDIR}/zot.test.port"

    docker network create kind 2>/dev/null || true
    local host_ip
    host_ip=$(docker network inspect kind \
        --format='{{range .IPAM.Config}}{{.Gateway}}{{end}}' \
        | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)

    if [ -z "${host_ip}" ]; then
        echo "ERROR: could not determine host IP from kind Docker network" >&2
        exit 1
    fi

    echo "${host_ip}" > "${BATS_FILE_TMPDIR}/host_ip"
    echo "kind network gateway (host IP from nodes): ${host_ip}" >&3

    local test_config="${BATS_FILE_TMPDIR}/zot_test_config.json"
    cat > "${test_config}" <<EOF
{
    "distSpecVersion": "1.1.1",
    "storage": {
        "rootDirectory": "${test_root}"
    },
    "http": {
        "address": "0.0.0.0",
        "port": "${test_port}"
    },
    "log": {
        "level": "debug",
        "output": "${test_root}/zot.log"
    },
    "extensions": {
        "sync": {
            "enable": true,
            "registries": [
                {
                    "urls": [
                        "https://index.docker.io"
                    ],
                    "onDemand": true,
                    "stream": true,
                    "tlsVerify": true
                },
                {
                    "urls": [
                        "https://ghcr.io"
                    ],
                    "onDemand": true,
                    "stream": true,
                    "tlsVerify": true
                }
            ]
        }
    }
}
EOF

    zot_serve "${ZOT_PATH}" "${test_config}"
    echo "waiting for zot-test to be reachable on port ${test_port}..." >&3
    wait_zot_reachable "${test_port}"
    echo "zot-test is reachable" >&3

    local kubeconfig="${BATS_FILE_TMPDIR}/kubeconfig"
    echo "${kubeconfig}" > "${BATS_FILE_TMPDIR}/kubeconfig.path"

    # Remove any leftover cluster from a previous run
    if "${KIND}" get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; then
        "${KIND}" delete cluster --name "${CLUSTER_NAME}"
    fi

    # Configure containerd so that zot is treated as a plain-HTTP registry.
    local kind_config="${BATS_FILE_TMPDIR}/kind_config.yaml"
    cat > "${kind_config}" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER_NAME}
kubeadmConfigPatches:
- |
  kind: KubeletConfiguration
  apiVersion: kubelet.config.k8s.io/v1beta1
  cgroupDriver: systemd
nodes:
- role: control-plane
  image: kindest/node:v1.28.7
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."${host_ip}:${test_port}"]
    endpoint = ["http://${host_ip}:${test_port}"]
EOF

    echo "creating kind cluster '${CLUSTER_NAME}'..." >&3
    "${KIND}" create cluster \
        --config "${kind_config}" \
        --kubeconfig "${kubeconfig}" \
        --wait 240s
    echo "kind cluster '${CLUSTER_NAME}' is ready" >&3

    # https://github.com/kubernetes/enhancements/tree/master/keps/sig-cluster-lifecycle/generic/1755-communicating-a-local-registry
    #
    # document the local registry
    cat <<EOF | kubectl --kubeconfig="${kubeconfig}" --context="kind-${CLUSTER_NAME}" apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "${host_ip}:${test_port}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF
}

function teardown_file() {
    local test_root
    test_root=$(cat "${BATS_FILE_TMPDIR}/test_root" 2>/dev/null || echo "")
    local kubeconfig
    kubeconfig=$(cat "${BATS_FILE_TMPDIR}/kubeconfig.path" 2>/dev/null || echo "")

    echo "=== zot-test log ===" >&3
    [ -n "${test_root}" ] && cat "${test_root}/zot.log" >&3 || true

    if [ -n "${kubeconfig}" ] && [ -f "${kubeconfig}" ]; then
        echo "=== kubernetes pod state ===" >&3
        kubectl --kubeconfig="${kubeconfig}" get pods -A >&3 || true
        echo "=== kubernetes events ===" >&3
        kubectl --kubeconfig="${kubeconfig}" get events \
            --sort-by='.lastTimestamp' >&3 || true
    fi

    zot_stop_all

    if "${KIND}" get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; then
        "${KIND}" delete cluster --name "${CLUSTER_NAME}"
    fi
}

@test "kubelet pulls image through streaming sync successfully" {
    local test_port
    test_port=$(cat "${BATS_FILE_TMPDIR}/zot.test.port")
    local host_ip
    host_ip=$(cat "${BATS_FILE_TMPDIR}/host_ip")
    local kubeconfig
    kubeconfig=$(cat "${BATS_FILE_TMPDIR}/kubeconfig.path")

    local pod_manifest="${BATS_FILE_TMPDIR}/debian-pod.yaml"
    cat > "${pod_manifest}" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: debian-streaming-test
spec:
  containers:
  - name: debian
    image: ${host_ip}:${test_port}/library/debian:stable-slim
    command: ["sh", "-c", "echo 'container started' && sleep 300"]
  restartPolicy: Never
EOF

    run kubectl --kubeconfig="${kubeconfig}" apply -f "${pod_manifest}"
    [ "$status" -eq 0 ]

    # Wait for the pod to become Ready.
    run kubectl --kubeconfig="${kubeconfig}" wait pod/debian-streaming-test \
        --for=condition=Ready \
        --timeout=120s
    [ "$status" -eq 0 ]

    # Confirm the pod reached the Running phase
    run kubectl --kubeconfig="${kubeconfig}" get pod debian-streaming-test \
        -o jsonpath='{.status.phase}'
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" = "Running" ]
}

@test "kubelet pulls multi-arch image through streaming sync successfully" {
    local test_port
    test_port=$(cat "${BATS_FILE_TMPDIR}/zot.test.port")
    local host_ip
    host_ip=$(cat "${BATS_FILE_TMPDIR}/host_ip")
    local kubeconfig
    kubeconfig=$(cat "${BATS_FILE_TMPDIR}/kubeconfig.path")

    # zot expects its config at /etc/zot/config.json. Provide it via ConfigMap
    # since the container has no shell to override the entrypoint.
    local cm_manifest="${BATS_FILE_TMPDIR}/zot-configmap.yaml"
    cat > "${cm_manifest}" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: zot-config
data:
  config.json: |
    {
      "storage": {"rootDirectory": "/var/lib/registry"},
      "http": {"address": "0.0.0.0", "port": "5000"},
      "log": {"level": "info"}
    }
EOF

    run kubectl --kubeconfig="${kubeconfig}" apply -f "${cm_manifest}"
    [ "$status" -eq 0 ]

    local pod_manifest="${BATS_FILE_TMPDIR}/zot-pod.yaml"
    cat > "${pod_manifest}" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: zot-multi-arch-streaming-test
spec:
  containers:
  - name: zot
    image: ${host_ip}:${test_port}/project-zot/zot:v2.1.18
    volumeMounts:
    - name: config-volume
      mountPath: /etc/zot
  volumes:
  - name: config-volume
    configMap:
      name: zot-config
  restartPolicy: Never
EOF

    run kubectl --kubeconfig="${kubeconfig}" apply -f "${pod_manifest}"
    [ "$status" -eq 0 ]

    # Wait for the pod to become Ready.
    run kubectl --kubeconfig="${kubeconfig}" wait pod/zot-multi-arch-streaming-test \
        --for=condition=Ready \
        --timeout=120s
    [ "$status" -eq 0 ]

    # Confirm the pod reached the Running phase
    run kubectl --kubeconfig="${kubeconfig}" get pod zot-multi-arch-streaming-test \
        -o jsonpath='{.status.phase}'
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" = "Running" ]
}
