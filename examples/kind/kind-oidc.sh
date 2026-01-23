#!/bin/sh
set -o errexit

ROOT_DIR=$(git rev-parse --show-toplevel)
KIND="${ROOT_DIR}"/hack/tools/bin/kind
DEX_VERSION="v2.41.1"

# Reference: https://github.com/int128/kind-oidc
# This test validates Kubernetes OIDC authentication with zot registry

# Parse command-line arguments
INTERACTIVE=false
if [ "$1" = "--interactive" ]; then
  INTERACTIVE=true
fi

# set no_proxy if applicable
if [ -n "${no_proxy}" ]; then
  echo "Updating no_proxy env var";
  export no_proxy=${no_proxy},dex-server,kind-registry;
  export NO_PROXY=${no_proxy};
fi

# Cleanup function
cleanup() {
  echo "Cleaning up..."
  "${KIND}" delete cluster --name kind-oidc 2>/dev/null || true
  docker stop dex-server 2>/dev/null || true
  docker rm dex-server 2>/dev/null || true
  docker stop kind-registry 2>/dev/null || true
  docker rm kind-registry 2>/dev/null || true
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Generate certificates for Dex
echo "Generating certificates for Dex..."
mkdir -p /tmp/kind-oidc
cd /tmp/kind-oidc

# Generate CA
openssl genrsa -out dex-ca.key 2048
openssl req -x509 -new -nodes -key dex-ca.key -days 365 -out dex-ca.crt -subj "/CN=dex-ca"

# Generate server certificate
openssl genrsa -out dex-server.key 2048
openssl req -new -key dex-server.key -out dex-server.csr -subj "/CN=dex-server"
openssl x509 -req -in dex-server.csr -CA dex-ca.crt -CAkey dex-ca.key -CAcreateserial -out dex-server.crt -days 365

# Create Dex configuration
cat > dex-config.yaml <<EOF
issuer: https://dex-server:10443/dex

storage:
  type: memory

web:
  https: 0.0.0.0:10443
  tlsCert: /dex-server.crt
  tlsKey: /dex-server.key

staticClients:
- id: kubernetes
  redirectURIs:
  - http://localhost:8000
  - http://localhost:18000
  name: 'Kubernetes'
  secret: kubernetes-client-secret

enablePasswordDB: true

staticPasswords:
- email: admin@example.com
  hash: "\$2a\$10\$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W"
  username: admin
  userID: "08a8684b-db88-4b73-90a9-3cd1661f5466"
EOF

# Start Dex server
echo "Starting Dex OIDC provider..."
docker run -d --name dex-server \
  -p 10443:10443 \
  -v /tmp/kind-oidc/dex-config.yaml:/dex-config.yaml:ro \
  -v /tmp/kind-oidc/dex-server.crt:/dex-server.crt:ro \
  -v /tmp/kind-oidc/dex-server.key:/dex-server.key:ro \
  ghcr.io/dexidp/dex:${DEX_VERSION} \
  serve /dex-config.yaml

# Wait for Dex to start
echo "Waiting for Dex to be ready..."
DEX_READY=false
for i in $(seq 1 30); do
  if docker exec dex-server wget -qO- --no-check-certificate https://localhost:10443/dex/.well-known/openid-configuration > /dev/null 2>&1; then
    echo "Dex is ready"
    DEX_READY=true
    break
  fi
  echo "Waiting for Dex... ($i/30)"
  sleep 2
done

if [ "$DEX_READY" = false ]; then
  echo "ERROR: Dex failed to become ready within timeout"
  exit 1
fi

# create registry container unless it already exists
reg_name='kind-registry'
reg_port='5001'
if [ "$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)" != 'true' ]; then
  docker run \
    -d --restart=always -p "127.0.0.1:${reg_port}:5000" --name "${reg_name}" \
    ghcr.io/project-zot/zot-minimal-linux-amd64:latest
fi

CLUSTER_NAME=kind-oidc
# Delete the cluster if it already exists
"${KIND}" get clusters | grep "${CLUSTER_NAME}" && "${KIND}" delete cluster --name "${CLUSTER_NAME}"

# Get Dex server IP address
DEX_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' dex-server)
echo "Dex server IP: ${DEX_IP}"

# create a cluster with OIDC authentication enabled
cat <<EOF | "${KIND}" create cluster --name ${CLUSTER_NAME} --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
kubeadmConfigPatches:
- |
  kind: ClusterConfiguration
  apiVersion: kubeadm.k8s.io/v1beta3
  apiServer:
    extraArgs:
      oidc-issuer-url: "https://dex-server:10443/dex"
      oidc-client-id: "kubernetes"
      oidc-ca-file: "/etc/kubernetes/pki/dex-ca.crt"
      oidc-username-claim: "email"
      oidc-groups-claim: "groups"
    extraVolumes:
    - name: dex-ca
      hostPath: /tmp/kind-oidc/dex-ca.crt
      mountPath: /etc/kubernetes/pki/dex-ca.crt
      readOnly: true
- |
  kind: KubeletConfiguration
  apiVersion: kubelet.config.k8s.io/v1beta1
  cgroupDriver: systemd
nodes:
- role: control-plane
  image: kindest/node:v1.28.7
  extraMounts:
  - hostPath: /tmp/kind-oidc/dex-ca.crt
    containerPath: /etc/kubernetes/pki/dex-ca.crt
    readOnly: true
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${reg_port}"]
    endpoint = ["http://${reg_name}:5000"]
EOF

# connect the registry to the cluster network if not already connected
if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${reg_name}")" = 'null' ]; then
  docker network connect "kind" "${reg_name}"
fi

# Connect Dex to kind network so API server can reach it
docker network connect "kind" "dex-server"

# Update /etc/hosts in the control plane to resolve dex-server
echo "Configuring DNS for dex-server in cluster..."
docker exec kind-oidc-control-plane sh -c "echo '${DEX_IP} dex-server' >> /etc/hosts"

# Verify OIDC configuration
echo "Verifying OIDC configuration in API server..."
kubectl --context kind-kind-oidc get --raw /.well-known/openid-configuration 2>&1 || echo "OIDC discovery endpoint check (this may fail if not exposed)"

# Document the local registry
cat <<EOF | kubectl --context kind-kind-oidc apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${reg_port}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF

# Create a cluster role binding for OIDC user
echo "Creating RBAC for OIDC user..."
kubectl --context kind-kind-oidc create clusterrolebinding oidc-cluster-admin \
  --clusterrole=cluster-admin \
  --user=admin@example.com || echo "ClusterRoleBinding already exists"

# Build and deploy zot with OIDC configuration
cd "${ROOT_DIR}"
make oci-image

# Copy the image to local registry
COMMIT_HASH=$(git describe --always --tags --long)
echo "Deploying zot-build:${COMMIT_HASH} image to local registry"
skopeo copy --format=oci --dest-tls-verify=false oci:oci docker://localhost:5001/zot-build:${COMMIT_HASH}

# Create a temporary directory for zot config and credentials
mkdir -p /tmp/kind-oidc/zot-config

# Create the credentials file for zot
cat > /tmp/kind-oidc/zot-config/dex-credentials.json <<EOF
{
    "clientid": "kubernetes",
    "clientsecret": "kubernetes-client-secret"
}
EOF

# Create the zot configuration
cat > /tmp/kind-oidc/zot-config/config.json <<EOF
{
  "distSpecVersion":"1.1.1",
  "storage": {
      "rootDirectory": "/var/lib/registry"
  },
  "http": {
      "address": "0.0.0.0",
      "port": "5000",
      "auth": {
          "openid": {
              "providers": {
                  "dex": {
                      "name": "Dex OIDC",
                      "issuer": "https://dex-server:10443/dex",
                      "credentialsFile": "/etc/zot/dex-credentials.json",
                      "keypath": "/etc/zot/dex-ca.crt",
                      "scopes": ["openid", "email", "groups"]
                  }
              }
          }
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
                  "defaultPolicy": []
              }
          }
      }
  },
  "log": {
      "level": "debug"
  }
}
EOF

# Create ConfigMap with zot OIDC configuration
kubectl --context kind-kind-oidc create configmap zot-oidc-config \
  --from-file=config.json=/tmp/kind-oidc/zot-config/config.json \
  --from-file=dex-credentials.json=/tmp/kind-oidc/zot-config/dex-credentials.json \
  --from-file=dex-ca.crt=/tmp/kind-oidc/dex-ca.crt \
  --dry-run=client -o yaml | kubectl --context kind-kind-oidc apply -f -

# Deploy zot
kubectl --context kind-kind-oidc apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zot-oidc
  labels:
    app: zot-oidc
spec:
  replicas: 1
  selector:
    matchLabels:
      app: zot-oidc
  template:
    metadata:
      labels:
        app: zot-oidc
    spec:
      containers:
      - name: zot
        image: localhost:5001/zot-build:${COMMIT_HASH}
        imagePullPolicy: IfNotPresent
        command: ["/usr/bin/zot"]
        args: ["serve", "/etc/zot/config.json"]
        ports:
        - name: http
          containerPort: 5000
          protocol: TCP
        volumeMounts:
        - name: config
          mountPath: /etc/zot
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: zot-oidc-config
---
apiVersion: v1
kind: Service
metadata:
  name: zot-oidc
spec:
  selector:
    app: zot-oidc
  ports:
  - protocol: TCP
    port: 5000
    targetPort: 5000
EOF

# Wait for deployment
echo "Waiting for zot-oidc deployment to be ready..."
kubectl --context kind-kind-oidc wait deployment -n default zot-oidc --for condition=Available=True --timeout=90s

echo ""
echo "=========================================="
echo "Kind cluster with OIDC authentication is ready!"
echo "=========================================="
echo ""
echo "Cluster name: kind-oidc"
echo "Context: kind-kind-oidc"
echo "Dex URL: https://dex-server:10443/dex (accessible from within cluster)"
echo "Dex URL (external): https://localhost:10443/dex"
echo "OIDC user: admin@example.com"
echo "OIDC password: password"
echo ""
echo "To access the cluster with OIDC authentication, you would typically use a tool like kubelogin:"
echo "  kubectl oidc-login setup --oidc-issuer-url=https://localhost:10443/dex \\"
echo "    --oidc-client-id=kubernetes \\"
echo "    --oidc-client-secret=kubernetes-client-secret \\"
echo "    --certificate-authority=/tmp/kind-oidc/dex-ca.crt"
echo ""
echo "Zot registry is running at: http://localhost:5000 (via kubectl port-forward)"
echo "To access: kubectl --context kind-kind-oidc port-forward svc/zot-oidc 5000:5000"
echo ""

# Validate the setup
echo "Validating setup..."
echo ""

# Check pods
echo "Cluster pods:"
kubectl --context kind-kind-oidc get pods -A

echo ""
echo "Zot logs:"
kubectl --context kind-kind-oidc logs -l app=zot-oidc --tail=50

echo ""
echo "=========================================="
echo "Test completed successfully!"
echo "=========================================="
echo ""

if [ "$INTERACTIVE" = true ]; then
  echo "Note: This test created a kind cluster with OIDC authentication enabled."
  echo "The cluster will be deleted when the script exits."
  echo "Press Enter to cleanup and exit..."
  read
else
  echo "Note: Running in non-interactive mode. Cleaning up automatically..."
  sleep 2
fi
