# OIDC Workload Identity Authentication

This document describes how to configure Zot to authenticate workloads using OIDC ID tokens, enabling secret-less authentication for automated workflows.

## Overview

OIDC Workload Identity authentication allows workloads (e.g., Kubernetes pods, CI/CD pipelines) to authenticate to Zot using OIDC ID tokens instead of static credentials. This is similar to how cloud providers implement "workload identity" features and how Kubernetes handles external OIDC authentication.

## Benefits

- **Secret-less Authentication**: No need to manage static credentials
- **Automatic Credential Rotation**: Tokens are short-lived and automatically rotated
- **Fine-grained Access Control**: Map OIDC claims to Zot identities and groups
- **Kubernetes Native**: Works seamlessly with Kubernetes ServiceAccount tokens
- **Standards-based**: Uses standard OIDC protocols

## Configuration

### Basic Configuration

Add OIDC workload identity configuration to your bearer authentication settings:

```json
{
  "http": {
    "auth": {
      "bearer": {
        "realm": "zot",
        "service": "zot-service",
        "oidc": {
          "issuer": "https://kubernetes.default.svc.cluster.local",
          "audiences": ["zot"]
        }
      }
    }
  }
}
```

### Configuration Options

- **`issuer`** (required): The OIDC issuer URL. This is the identity provider that signs the tokens.
  - Example: `"https://kubernetes.default.svc.cluster.local"`
  - Example: `"https://token.actions.githubusercontent.com"`

- **`audiences`** (required): List of acceptable audiences for the OIDC token. At least one must be specified.
  - Example: `["zot", "https://zot.example.com"]`

- **`claimMapping.username`** (optional): Which OIDC claim to use as the username. Defaults to `"sub"`.
  - Acceptable values: `"sub"`, `"email"`, `"preferred_username"`, `"name"`, or any custom claim
  - Example: `"preferred_username"`

- **`jwksDiscoveryUrl`** (optional): Override the JWKS discovery URL. If not provided, it defaults to `{issuer}/.well-known/openid-configuration`.

- **`skipIssuerVerification`** (optional): Skip issuer verification (for testing only). Default: `false`.

### Complete Example

```json
{
  "distSpecVersion": "1.1.1",
  "storage": {
    "rootDirectory": "/tmp/zot"
  },
  "http": {
    "address": "127.0.0.1",
    "port": "8080",
    "auth": {
      "bearer": {
        "realm": "zot",
        "service": "zot-service",
        "oidc": {
          "issuer": "https://kubernetes.default.svc.cluster.local",
          "audiences": ["zot", "https://zot.example.com"],
          "claimMapping": {
            "username": "sub"
          }
        }
      }
    },
    "accessControl": {
      "repositories": {
        "**": {
          "policies": [
            {
              "users": ["system:serviceaccount:default:flux-controller"],
              "actions": ["read", "create", "update", "delete"]
            }
          ]
        }
      }
    }
  },
  "log": {
    "level": "info"
  }
}
```

## Usage

### Kubernetes ServiceAccount Tokens

When running in Kubernetes, workloads can use their ServiceAccount tokens to authenticate:

```bash
# Get the ServiceAccount token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Use it to authenticate to Zot
curl -H "Authorization: Bearer $TOKEN" https://zot.example.com/v2/_catalog
```

### Flux CD Integration

Flux CD can use OIDC workload identity to authenticate to Zot without storing credentials:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: zot-repo
  namespace: flux-system
spec:
  url: https://zot.example.com/v2/
  type: oci
  provider: generic
```

### GitHub Actions

GitHub Actions can use OIDC tokens to authenticate:

```yaml
- name: Login to Zot
  run: |
    TOKEN=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=zot" | jq -r .value)
    echo $TOKEN | docker login -u oauth --password-stdin zot.example.com
```

## Token Claims

### Required Claims

- **`iss`**: Issuer URL (must match configured issuer)
- **`aud`**: Audience (must match one of the configured audiences)
- **`sub`**: Subject (used as username by default)
- **`exp`**: Expiration time
- **`iat`**: Issued at time

### Optional Claims

- **`groups`**: Array of group names for authorization
- **`preferred_username`**: Can be used as username with claim mapping
- **`email`**: Can be used as username with claim mapping
- **`name`**: Can be used as username with claim mapping

### Example Token Payload

```json
{
  "iss": "https://kubernetes.default.svc.cluster.local",
  "aud": "zot",
  "sub": "system:serviceaccount:default:flux-controller",
  "exp": 1705258800,
  "iat": 1705255200,
  "groups": ["system:serviceaccounts", "system:authenticated"]
}
```

## Access Control

Use Zot's access control policies to grant permissions based on the OIDC identity:

```json
{
  "accessControl": {
    "repositories": {
      "app/**": {
        "policies": [
          {
            "users": ["system:serviceaccount:prod:app-controller"],
            "actions": ["read", "create", "update"]
          }
        ]
      },
      "**": {
        "policies": [
          {
            "users": ["system:serviceaccount:default:admin"],
            "actions": ["read", "create", "update", "delete"]
          }
        ],
        "defaultPolicy": ["read"]
      }
    }
  }
}
```

## Compatibility

### Traditional Bearer Authentication

OIDC workload identity can coexist with traditional bearer authentication. If both are configured, Zot will try OIDC authentication first, then fall back to traditional bearer token authentication:

```json
{
  "http": {
    "auth": {
      "bearer": {
        "realm": "https://auth.myreg.io/auth/token",
        "service": "myauth",
        "cert": "/etc/zot/auth.crt",
        "oidc": {
          "issuer": "https://kubernetes.default.svc.cluster.local",
          "audiences": ["zot"]
        }
      }
    }
  }
}
```

### Other Authentication Methods

OIDC workload identity is only available with bearer authentication. For other authentication methods (htpasswd, LDAP, OAuth2 for humans), continue using the existing configuration options.

## Troubleshooting

### Enable Debug Logging

Set log level to `debug` to see detailed authentication logs:

```json
{
  "log": {
    "level": "debug"
  }
}
```

### Common Issues

1. **Token verification failed**: Check that the issuer URL is correct and reachable from Zot.

2. **Audience not accepted**: Ensure the token's `aud` claim matches one of the configured audiences.

3. **Token expired**: OIDC tokens are typically short-lived. Ensure your workload is obtaining fresh tokens.

4. **No username found**: Check the claim mapping configuration and ensure the specified claim exists in the token.

5. **JWKS endpoint not reachable**: Verify network connectivity to the OIDC issuer's JWKS endpoint.

## Security Considerations

1. **Token Expiration**: Always use short-lived tokens (typically 1 hour or less).

2. **Audience Validation**: Always specify audiences to prevent token reuse across services.

3. **TLS**: Use TLS for all communication to protect tokens in transit.

4. **Issuer Verification**: Never disable issuer verification in production.

5. **Access Control**: Always configure access control policies to limit what authenticated workloads can do.

## References

- [OIDC Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [Kubernetes OIDC Authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens)
- [Flux Workload Identity RFC](https://github.com/fluxcd/flux2/tree/main/rfcs/0010-multi-tenant-workload-identity)
