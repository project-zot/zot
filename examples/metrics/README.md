
A quick zot Metrics setup can be deployed locally in a kind cluster.
It contains:
 * a Prometheus server deployed through an Operator
 * a dist-spec-only zot deployment (a pod with 2 containers: the zot server & the node exporter)
 * a zot with all extensions enabled

## Prerequisites
  * [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)
  * [Kind](https://kind.sigs.k8s.io/)
  * [Docker](https://www.docker.com/)

In case the prerequisites tool list is not fulfilled the script will install them (needs root privileges)

## Metrics setup
To run a quick setup:

```
./kind-setup.sh

```

At the end of the script below ports are locally available (using *kubectl port-forward*) to easy access the Prometheus & zot servers on the host:
 * 9090 - for accessing Prometheus server
 * 5000 - for zot with all extensions enabled
 * 5050 - for accessing dist-spec-only zot server
 * 5051 - for zxp access (a Prometheus Node exporter)

