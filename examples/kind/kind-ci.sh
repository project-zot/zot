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

CLUSTER_NAME=kind
## Delete the cluster if it already exist
kind get clusters | grep ${CLUSTER_NAME} &&  kind delete cluster --name ${CLUSTER_NAME}

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

# https://github.com/kubernetes/enhancements/tree/master/keps/sig-cluster-lifecycle/generic/1755-communicating-a-local-registry
#
# document the local registry
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

## Deploy prometheus operator
kubectl create -f examples/metrics/kubernetes/prometheus/bundle.yaml

## Deploy the Kubernetes objects for RBAC, prometheus CRD and deploy the service
kubectl apply -f examples/metrics/kubernetes/prometheus/prom_rbac.yaml
kubectl apply -f examples/metrics/kubernetes/prometheus/prometheus.yaml
kubectl apply -f examples/metrics/kubernetes/prometheus/prom_service.yaml

make oci-image
# copy the image
COMMIT_HASH=$(git describe --always --tags --long)
echo "deploy zot-build:${COMMIT_HASH} image to local registry"
skopeo copy --format=oci --dest-tls-verify=false oci:oci docker://localhost:5001/zot-build:${COMMIT_HASH}

# deploy the image
kubectl apply -f examples/metrics/kubernetes/zot-extended/deployment.yaml
kubectl patch deployment/zot-extended --patch-file examples/metrics/kubernetes/zot-extended/patch-deployment.yaml
kubectl set image deployment/zot-extended zot-extended=localhost:5001/zot-build:${COMMIT_HASH}
kubectl apply -f examples/metrics/kubernetes/zot-extended/service.yaml
kubectl apply -f examples/metrics/kubernetes/zot-extended/servicemonitor.yaml

# check for availability
echo "Waiting for deployment/zot-extended to be ready ..."
kubectl wait deployment -n default zot-extended --for condition=Available=True --timeout=90s
kubectl wait deployment -n default prometheus-operator --for condition=Available=True --timeout=90s

kubectl port-forward svc/prometheus 9090 --address='0.0.0.0' &
echo "Kind cluster status before sleep:"
kubectl get pods -A
# Put enough amount of time for prometheus scraping take place
sleep 90
echo "Kind cluster status:"
kubectl get pods -A
echo "zot-extended logs:"
kubectl logs -l app=zot-extended --tail=-1

containername=`curl -s http://localhost:9090/api/v1/query?query=up | jq '.data.result[].metric.container'`
echo "containername=${containername}"
if [ "${containername}" != '"zot-extended"' ]; then
    exit 1
fi

containerup=`curl -s http://localhost:9090/api/v1/query?query=up | jq '.data.result[].value[1]'`
echo "containerup=${containerup}"
if [ "${containerup}" != '"1"' ]; then
    exit 1
fi

zotinfo=`curl -s http://localhost:9090/api/v1/query?query=zot_info | jq '.data.result[].value[1]'`
echo "zotinfo=${zotinfo}"
if [ "${zotinfo}" != '"0"' ]; then
    exit 1
fi
