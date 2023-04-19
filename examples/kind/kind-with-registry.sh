#!/bin/sh
set -o errexit

# Reference: https://kind.sigs.k8s.io/docs/user/local-registry/

# set no_proxy if applicable
if [ ! -z "${no_proxy}" ]; then 
  echo "Updating no_proxy env var";
  export no_proxy=${no_proxy},kind-registry;
  export NO_PROXY=${no_proxy};
fi

# create registry container unless it already exists
reg_name='kind-registry'
reg_port='5001'
if [ "$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)" != 'true' ]; then
  docker run \
    -d --restart=always -p "127.0.0.1:${reg_port}:5000" --name "${reg_name}" \
    ghcr.io/project-zot/zot-minimal-linux-amd64:latest
fi

# create a cluster with the local registry enabled in containerd
cat <<EOF | kind create cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${reg_port}"]
    endpoint = ["http://${reg_name}:5000"]
EOF

# connect the registry to the cluster network if not already connected
if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${reg_name}")" = 'null' ]; then
  docker network connect "kind" "${reg_name}"
fi

# Document the local registry
# https://github.com/kubernetes/enhancements/tree/master/keps/sig-cluster-lifecycle/generic/1755-communicating-a-local-registry
cat <<EOF | kubectl apply -f -
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

# Copy an image
skopeo copy --format=oci --dest-tls-verify=false docker://gcr.io/google-samples/hello-app:1.0 docker://localhost:5001/hello-app:1.0

# Deploy
kubectl create deployment hello-server --image=localhost:5001/hello-app:1.0

# Check
echo "Waiting for deployment/hello-server to be ready ..."
kubectl wait deployment -n default hello-server --for condition=Available=True --timeout=90s

# cleanup
echo "Press a key to begin cleanup ..."
read KEYPRESS
kind delete cluster
docker stop kind-registry
docker rm kind-registry
