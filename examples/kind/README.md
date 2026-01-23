# Kind Examples

This directory contains scripts for running zot in Kubernetes using [kind](https://kind.sigs.k8s.io/) (Kubernetes IN Docker).

## Scripts

### kind-with-registry.sh

A simple example that demonstrates:
- Creating a kind cluster
- Running a local registry (zot-minimal)
- Configuring containerd to use the local registry
- Deploying a sample application

Usage:
```bash
./kind-with-registry.sh
```

### kind-ci.sh

CI test that validates:
- Kind cluster setup with local registry
- Prometheus operator deployment
- Zot extended deployment with metrics
- Prometheus scraping of zot metrics

Usage:
```bash
./kind-ci.sh
```

This script is used in the nightly CI workflow.

### kind-oidc.sh

Kubernetes OIDC authentication test that demonstrates:
- Setting up a Dex OIDC provider
- Creating a kind cluster with OIDC authentication configured for the Kubernetes API server
- Deploying zot with OIDC authentication
- Configuring RBAC for OIDC users

This test validates that:
1. The Kubernetes API server can authenticate users via OIDC
2. Zot can be deployed and configured with OIDC authentication in Kubernetes
3. The complete OIDC authentication flow works in a Kubernetes environment

#### Prerequisites

- Docker
- kind (installed via `make` or available in `hack/tools/bin/kind`)
- kubectl
- openssl
- skopeo

#### Usage

```bash
# Run in non-interactive mode (default, suitable for CI)
./kind-oidc.sh

# Run in interactive mode (keeps cluster running until you press Enter)
./kind-oidc.sh --interactive
```

The script will:
1. Generate TLS certificates for Dex
2. Start a Dex OIDC provider in a Docker container
3. Create a kind cluster with OIDC configuration
4. Deploy zot with OIDC authentication enabled
5. Configure RBAC for OIDC users
6. Wait for user input before cleanup

#### OIDC Configuration Details

- **OIDC Provider**: Dex (https://dexidp.io/)
- **Issuer URL**: `https://dex-server:10443/dex`
- **Client ID**: `kubernetes`
- **Test User**: `admin@example.com`
- **Test Password**: `password`

The Kubernetes API server is configured with the following OIDC flags:
- `--oidc-issuer-url`: Points to the Dex server
- `--oidc-client-id`: Set to "kubernetes"
- `--oidc-username-claim`: Uses the "email" claim
- `--oidc-groups-claim`: Uses the "groups" claim
- `--oidc-ca-file`: CA certificate for TLS verification

#### Testing OIDC Authentication

To test OIDC authentication with kubectl, you can use [kubelogin](https://github.com/int128/kubelogin):

```bash
# Install kubelogin
kubectl krew install oidc-login

# Setup OIDC authentication
kubectl oidc-login setup \
  --oidc-issuer-url=https://localhost:10443/dex \
  --oidc-client-id=kubernetes \
  --oidc-client-secret=kubernetes-client-secret \
  --certificate-authority=/tmp/kind-oidc/dex-ca.crt

# Use OIDC authentication
kubectl --user=oidc get nodes
```

#### Architecture

```
┌─────────────────────────────────────────────┐
│  Host Machine                                │
│                                              │
│  ┌──────────────┐      ┌─────────────────┐  │
│  │ Dex Server   │      │  Kind Cluster   │  │
│  │ (Docker)     │◄─────┤  ┌───────────┐  │  │
│  │              │      │  │ API Server│  │  │
│  │ Port: 10443  │      │  │ + OIDC    │  │  │
│  └──────────────┘      │  └───────────┘  │  │
│                        │  ┌───────────┐  │  │
│                        │  │ Zot Pod   │  │  │
│                        │  │ + OIDC    │  │  │
│                        │  └───────────┘  │  │
│                        └─────────────────┘  │
└─────────────────────────────────────────────┘
```

The Dex server and kind cluster are connected via Docker's "kind" network, allowing the Kubernetes API server to communicate with Dex for token validation.

#### Cleanup

The script automatically cleans up resources when it exits:
- Deletes the kind cluster
- Stops and removes the Dex container
- Stops and removes the registry container

#### References

- [Kind documentation](https://kind.sigs.k8s.io/)
- [Kubernetes OIDC authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens)
- [Dex OIDC provider](https://dexidp.io/)
- [kind-oidc example](https://github.com/int128/kind-oidc)

## Common Issues

### Certificate Errors

If you encounter certificate errors, ensure that:
- OpenSSL is installed and available
- The certificates are generated correctly
- The CA certificate is mounted to the correct path in the kind cluster

### Network Issues

If the Kubernetes API server cannot reach Dex:
- Verify that Dex is running: `docker ps | grep dex-server`
- Check that both containers are on the same network: `docker network inspect kind`
- Verify DNS resolution in the control plane: `docker exec kind-oidc-control-plane cat /etc/hosts`

### OIDC Token Validation Failures

If OIDC authentication fails:
- Check the API server logs: `docker logs kind-oidc-control-plane`
- Verify the OIDC configuration: `kubectl --context kind-kind-oidc -n kube-system describe pod <api-server-pod>`
- Ensure the issuer URL is accessible from within the cluster
