# OIDC Workload Identity Authentication

This document describes how to configure Zot to authenticate workloads using OIDC ID tokens, enabling secret-less authentication for automated workflows.

## Overview

OIDC Workload Identity authentication allows workloads (e.g., Kubernetes pods, CI/CD pipelines) to authenticate to Zot using OIDC ID tokens instead of static credentials. This is similar to how cloud providers implement "workload identity" features and how Kubernetes handles external OIDC authentication.

## Benefits

- **Secret-less Authentication**: No need to manage static credentials
- **Automatic Credential Rotation**: Tokens are short-lived and automatically rotated
- **Fine-grained Access Control**: Map OIDC claims to Zot identities and groups using CEL expressions
- **Kubernetes Native**: Works seamlessly with Kubernetes ServiceAccount tokens
- **Multi-Provider Support**: Configure multiple OIDC issuers for different workload types (e.g. multiple clusters)
- **Standards-based**: Uses standard OIDC protocols

## Configuration

### Basic Configuration

Add OIDC workload identity configuration to your bearer authentication settings. The `oidc` field accepts an array of provider configurations:

```json
{
  "http": {
    "auth": {
      "bearer": {
        "realm": "zot",
        "service": "zot-service",
        "oidc": [
          {
            "issuer": "https://kubernetes.default.svc.cluster.local",
            "audiences": ["zot"]
          }
        ]
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

- **`claimMapping`** (optional): CEL-based configuration for validating and mapping OIDC claims.
  - **`variables`**: List of variables to extract from claims using CEL expressions
  - **`validations`**: List of validation rules with CEL expressions
  - **`username`**: CEL expression to extract the username. Default: `"claims.iss + '/' + claims.sub"`
  - **`groups`**: CEL expression to extract groups. Default: none (no groups extracted)

- **`certificateAuthority`** (optional): PEM-encoded CA certificate to validate the OIDC provider's TLS certificate. Useful when the OIDC issuer uses a private CA (e.g., Kubernetes API server with a self-signed certificate). Mutually exclusive with `certificateAuthorityFile`.

- **`certificateAuthorityFile`** (optional): Path to a PEM-encoded CA certificate file to validate the OIDC provider's TLS certificate. Mutually exclusive with `certificateAuthority`.

- **`skipIssuerVerification`** (optional): Skip issuer verification (for testing only). Default: `false`.

### CEL Expressions

Zot uses [Common Expression Language (CEL)](https://github.com/google/cel-go) for flexible claim validation and mapping. CEL expressions have access to:

- **`claims`**: The OIDC token claims as a map (e.g., `claims.sub`, `claims.email`)
- **`vars`**: Previously extracted variables (for use in validations and username/groups expressions)

#### Example CEL Expressions

| Expression | Description |
|------------|-------------|
| `claims.sub` | Extract the subject claim |
| `claims.email` | Extract the email claim |
| `claims.groups` | Extract the groups claim |
| `claims['kubernetes.io/serviceaccount/namespace']` | Extract claims with special characters |
| `claims.repository_owner + '/' + claims.sub` | Concatenate multiple claims |
| `claims.email.split('@')[0]` | Extract username from email |
| `claims.org in ['allowed-org-1', 'allowed-org-2']` | Check if org is in allowed list |
| `claims.email_verified == true` | Validate email is verified |

### Complete Example

In the example below, the username is mapped from both the issuer and subject
claims to uniquely identify Kubernetes ServiceAccounts across different clusters.
Note that `claims.iss + '/' + claims.sub` is the default username mapping if none
is specified (so the whole `claimMapping` section could be omitted in this example).

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
        "oidc": [
          {
            "issuer": "https://kubernetes.default.svc.cluster.local",
            "audiences": ["zot", "https://zot.example.com"],
            "claimMapping": {
              "username": "claims.iss + '/' + claims.sub"
            }
          }
        ]
      }
    },
    "accessControl": {
      "repositories": {
        "**": {
          "policies": [
            {
              "users": ["https://kubernetes.default.svc.cluster.local/system:serviceaccount:flux-system:source-controller"],
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

### Configuration with Custom CA

When the OIDC issuer uses a private CA (e.g., Kubernetes API server), you can configure the CA certificate inline or via a file path:

```json
{
  "http": {
    "auth": {
      "bearer": {
        "oidc": [
          {
            "issuer": "https://kubernetes.default.svc.cluster.local",
            "audiences": ["zot"],
            "certificateAuthorityFile": "/etc/zot/k8s-ca.pem"
          }
        ]
      }
    }
  }
}
```

Alternatively, you can embed the CA certificate directly using `certificateAuthority`:

```json
{
  "http": {
    "auth": {
      "bearer": {
        "oidc": [
          {
            "issuer": "https://kubernetes.default.svc.cluster.local",
            "audiences": ["zot"],
            "certificateAuthority": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
          }
        ]
      }
    }
  }
}
```

### Advanced Configuration with CEL Validations

Use CEL expressions to validate claims and extract complex usernames:

```json
{
  "http": {
    "auth": {
      "bearer": {
        "oidc": [
          {
            "issuer": "https://token.actions.githubusercontent.com",
            "audiences": ["zot"],
            "claimMapping": {
              "variables": [
                {
                  "name": "repo",
                  "expression": "claims.repository"
                },
                {
                  "name": "owner",
                  "expression": "claims.repository_owner"
                }
              ],
              "validations": [
                {
                  "expression": "vars.owner == 'my-org'",
                  "message": "only my-org repositories are allowed"
                },
                {
                  "expression": "claims.ref.startsWith('refs/heads/')",
                  "message": "must be a branch reference"
                }
              ],
              "username": "vars.repo",
              "groups": "['github-actions', 'ci']"
            }
          }
        ]
      }
    }
  }
}
```

### Multiple OIDC Providers

Configure multiple OIDC providers to support different identity sources. Zot will try each provider in order until one successfully authenticates the token:

```json
{
  "http": {
    "auth": {
      "bearer": {
        "oidc": [
          {
            "issuer": "https://kubernetes.default.svc.cluster.local",
            "audiences": ["zot"],
            "claimMapping": {
              "variables": [
                {
                  "name": "ns",
                  "expression": "claims['kubernetes.io/serviceaccount/namespace']"
                },
                {
                  "name": "sa",
                  "expression": "claims['kubernetes.io/serviceaccount/service-account.name']"
                }
              ],
              "username": "vars.ns + ':' + vars.sa",
              "groups": "['k8s-workloads']"
            }
          },
          {
            "issuer": "https://token.actions.githubusercontent.com",
            "audiences": ["zot"],
            "claimMapping": {
              "username": "claims.repository",
              "groups": "['github-actions']"
            }
          }
        ]
      }
    }
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

### Flux Integration

Flux can use Kubernetes ServiceAccount tokens to authenticate to Zot without secrets:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: zot-repo
  namespace: flux-system
spec:
  url: oci://zot.example.com/v2/manifests
  credentials: ServiceAccountToken
  serviceAccountName: my-tenant-sa # optional. if omitted, defaults to the source-controller ServiceAccount
```

Note: The configuration above is currently a proposal from the Flux maintainers
and may change until officially released. For more details, see this
[RFC](https://github.com/fluxcd/flux2/issues/5681).

### GitHub Actions

GitHub Actions can use OIDC tokens to authenticate:

```yaml
- name: Login to Zot
  run: |
    TOKEN=$(curl -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
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

- **`groups`**: Array of group names for authorization (requires CEL `groups` expression)
- **`preferred_username`**: Can be used as username with CEL expression
- **`email`**: Can be used as username with CEL expression
- **`name`**: Can be used as username with CEL expression

### Example Token Payload

```json
{
  "iss": "https://kubernetes.default.svc.cluster.local",
  "aud": ["zot"],
  "sub": "system:serviceaccount:flux-system:source-controller",
  "exp": 1705258800,
  "iat": 1705255200,
  "kubernetes.io/serviceaccount/namespace": "flux-system",
  "kubernetes.io/serviceaccount/service-account.name": "source-controller"
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
        "oidc": [
          {
            "issuer": "https://kubernetes.default.svc.cluster.local",
            "audiences": ["zot"]
          }
        ]
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

4. **CEL expression error**: Check the CEL expression syntax. Use `claims.field` for simple fields or `claims['field-name']` for fields with special characters.

5. **Validation failed**: Check that your token claims satisfy all configured validation expressions.

6. **JWKS endpoint not reachable**: Verify network connectivity to the OIDC issuer's JWKS endpoint. Note: Zot lazily initializes the OIDC provider on first authentication, so startup won't fail if the issuer is temporarily unreachable. If the issuer uses a private CA, configure `certificateAuthority` or `certificateAuthorityFile` for the corresponding OIDC provider.

7. **No username found**: Ensure the CEL expression for username evaluates to a non-empty string. Check that the required claims exist in the token.

## Security Considerations

1. **Token Expiration**: Always use short-lived tokens (typically 1 hour or less).

2. **Audience Validation**: Always specify audiences to prevent token reuse across services.

3. **TLS**: Use TLS for all communication to protect tokens in transit.

4. **Issuer Verification**: Never disable issuer verification in production.

5. **Access Control**: Always configure access control policies to limit what authenticated workloads can do.

6. **CEL Validations**: Use CEL validations to enforce additional security constraints (e.g., require email verification, restrict to specific organizations).

## References

- [OIDC Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [CEL Language Definition](https://github.com/google/cel-spec)
- [Kubernetes OIDC Authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens)
- [Flux Workload Identity RFC](https://github.com/fluxcd/flux2/tree/main/rfcs/0010-multi-tenant-workload-identity)
- [GitHub Actions OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
