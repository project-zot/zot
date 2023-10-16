#!/bin/bash

#set -x
set -e

CLUSTER_NAME=zot

# Script tested with below kubectl & kind versions
KUBECTL_VERSION=v1.27.3
KIND_VERSION=v0.20.0

function install_bin() {
    if [ "$EUID" -ne 0 ]
        then echo "Please run as root/sudo"
        exit 1
    fi
    curl -Lo ./$2 $1
    chmod +x ./$2
    yes | mv ./$2 /usr/local/bin/$2
}

## Install kubectl & kind if not available on the system

# Kubectl
kubectl > /dev/null 2>&1 || install_bin https://storage.googleapis.com/kubernetes-release/release/${KUBECTL_VERSION}/bin/`uname | awk '{print tolower($0)}'`/amd64/kubectl kubectl

# Kind
kind version || install_bin https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-$(uname)-amd64 kind

## Delete the cluster if it already exist
kind get clusters | grep ${CLUSTER_NAME} &&  kind delete cluster --name ${CLUSTER_NAME}

kind create cluster --name ${CLUSTER_NAME}

docker pull quay.io/prometheus-operator/prometheus-operator:v0.51.2
docker pull quay.io/prometheus-operator/prometheus-config-reloader:v0.51.2
docker pull quay.io/prometheus/prometheus:v2.22.1

kind load docker-image quay.io/prometheus-operator/prometheus-operator:v0.51.2 --name ${CLUSTER_NAME}
kind load docker-image quay.io/prometheus-operator/prometheus-config-reloader:v0.51.2 --name ${CLUSTER_NAME}
kind load docker-image quay.io/prometheus/prometheus:v2.22.1 --name ${CLUSTER_NAME}

## Build zot & zxp images
make -C ../../ binary-container
make -C ../../ binary-minimal-container
make -C ../../ binary-exporter-container

kind load docker-image zot-build:latest --name ${CLUSTER_NAME}
kind load docker-image zot-minimal:latest --name ${CLUSTER_NAME}
kind load docker-image zxp:latest --name ${CLUSTER_NAME}

## Deploy prometheus operator
kubectl create -f kubernetes/prometheus/bundle.yaml

## Deploy the Kubernetes objects for RBAC, prometheus CRD and deploy the service
kubectl apply -f kubernetes/prometheus/prom_rbac.yaml
kubectl apply -f kubernetes/prometheus/prometheus.yaml
kubectl apply -f kubernetes/prometheus/prom_service.yaml

sleep 10
## Deploy zot extended & minimal in 2 separate deployments
## Deploy Prometheus operator servicemonitor CRD instances for prometheus to be able to scrape metrics from zot extended & the node exporter
kubectl apply -f kubernetes/zot-extended/deployment.yaml
kubectl apply -f kubernetes/zot-extended/service.yaml
kubectl apply -f kubernetes/zot-extended/servicemonitor.yaml

kubectl apply -f kubernetes/zot-minimal/deployment.yaml
kubectl apply -f kubernetes/zot-minimal/service.yaml
kubectl apply -f kubernetes/zot-minimal/exporter-service.yaml
kubectl apply -f kubernetes/zot-minimal/exporter-servicemonitor.yaml

sleep 10
## For being able to access prometheus, zot & exporter on localhost ports
kubectl port-forward svc/prometheus 9090 --address='0.0.0.0' &
kubectl port-forward svc/zot-extended 5000 --address='0.0.0.0' &
kubectl port-forward svc/zot-minimal 5050 --address='0.0.0.0' &
kubectl port-forward svc/zot-exporter 5051 --address='0.0.0.0' &

