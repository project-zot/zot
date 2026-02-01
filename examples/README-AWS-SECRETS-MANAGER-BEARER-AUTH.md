# AWS Secrets Manager Bearer Authentication

This document describes how to configure Zot to retrieve JWT verification keys from AWS Secrets Manager, enabling dynamic key rotation without restarting the registry.

## Overview

AWS Secrets Manager bearer authentication allows Zot to retrieve public keys for JWT verification from AWS Secrets Manager instead of loading them from a static file on disk. This is useful when keys need to be rotated without downtime, or when the same keys are shared across multiple Zot instances.

Zot periodically refreshes the keys from AWS Secrets Manager, so key rotations are picked up automatically.

## Benefits

- **Dynamic Key Rotation**: Rotate public keys in AWS Secrets Manager without restarting Zot
- **Centralized Key Management**: Manage verification keys for multiple Zot instances in a single place
- **Lazy Loading**: Keys are fetched on first authentication, so startup is not blocked by network issues
- **Caching**: Keys are cached locally and refreshed periodically to minimize API calls
- **Multiple Keys**: Support multiple key IDs (`kid`) for seamless key rotation

## Configuration

### Basic Configuration

Add AWS Secrets Manager configuration to your bearer authentication settings:

```json
{
  "http": {
    "auth": {
      "bearer": {
        "realm": "zot",
        "service": "zot-service",
        "awsSecretsManager": {
          "region": "us-east-1",
          "secretName": "zot/jwt-verification-keys"
        }
      }
    }
  }
}
```

### Configuration Options

- **`region`** (required): The AWS region where the secret is stored.
  - Example: `"us-east-1"`

- **`secretName`** (required): The name or ARN of the secret in AWS Secrets Manager.
  - Example: `"zot/jwt-verification-keys"`
  - Example: `"arn:aws:secretsmanager:us-east-1:123456789012:secret:zot/keys-AbCdEf"`

- **`refreshInterval`** (optional): How often to refresh keys from AWS Secrets Manager. Default: `1m` (1 minute).
  - Example: `"5m"` (5 minutes)
  - Example: `"30s"` (30 seconds)

## Secret Format

The secret stored in AWS Secrets Manager must be a JSON object where each key is a key ID (`kid`) and each value is either a PEM-encoded public key or a JWKS key set with a single key:

### PEM Format

```json
{
  "key-id-1": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----\n",
  "key-id-2": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG...\n-----END PUBLIC KEY-----\n"
}
```

### JWKS Format

Each value can also be a JWKS key set containing a single key:

```json
{
  "key-id-1": "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"...\"}]}"
}
```

### Supported Key Types

- **Ed25519** (EdDSA) - Recommended for new deployments
- **RSA** (RS256, RS384, RS512, PS256, PS384, PS512)
- **ECDSA** (ES256, ES384, ES512)

## Complete Example

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
        "awsSecretsManager": {
          "region": "us-east-1",
          "secretName": "zot/jwt-verification-keys",
          "refreshInterval": "5m"
        }
      }
    },
    "accessControl": {
      "repositories": {
        "**": {
          "policies": [
            {
              "users": ["service-account-1"],
              "actions": ["read", "create", "update"]
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

## JWT Token Requirements

JWTs presented to Zot must include a `kid` (Key ID) header that matches one of the key IDs in the secret. This is how Zot selects the correct public key for verification.

### Example JWT Header

```json
{
  "alg": "EdDSA",
  "kid": "key-id-1",
  "typ": "JWT"
}
```

### Example JWT Payload

```json
{
  "iss": "https://auth.example.com",
  "sub": "service-account-1",
  "aud": ["zot"],
  "exp": 1705258800,
  "iat": 1705255200,
  "access": [
    {
      "type": "repository",
      "name": "my-app",
      "actions": ["pull", "push"]
    }
  ]
}
```

## Key Rotation

To rotate keys without downtime:

1. **Add the new key** to the secret in AWS Secrets Manager alongside the existing key(s):
   ```json
   {
     "old-key-id": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
     "new-key-id": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
   }
   ```

2. **Update your token issuer** to sign new tokens with the new key ID.

3. **Wait for the refresh interval** to elapse. Zot will automatically pick up the new key.

4. **Remove the old key** from the secret once all tokens signed with the old key have expired.

## Compatibility

### With OIDC Workload Identity

AWS Secrets Manager bearer authentication can coexist with OIDC workload identity. If both are configured, Zot will try OIDC authentication first, then fall back to traditional bearer token authentication using keys from AWS Secrets Manager:

```json
{
  "http": {
    "auth": {
      "bearer": {
        "realm": "zot",
        "service": "zot-service",
        "awsSecretsManager": {
          "region": "us-east-1",
          "secretName": "zot/jwt-verification-keys"
        },
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

### With Static Certificate

AWS Secrets Manager and the static `cert` option are mutually exclusive. Zot will refuse to start if both are configured.

## AWS Authentication

Zot uses the default AWS credential chain to authenticate with AWS Secrets Manager. This means you can use any of the following:

- **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- **Shared credentials file**: `~/.aws/credentials`
- **IAM role** (for EC2, ECS, or EKS workloads)
- **Web identity token** (for EKS with IRSA)

### Required IAM Permissions

The IAM principal used by Zot needs the following permission:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:zot/jwt-verification-keys-*"
    }
  ]
}
```

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

1. **"region must be specified"**: The `region` field is required in the configuration.

2. **"secret name must be specified"**: The `secretName` field is required in the configuration.

3. **"failed to load AWS configuration"**: Check that AWS credentials are available and valid.

4. **"failed to retrieve secret"**: Verify the secret exists in the specified region and the IAM principal has `secretsmanager:GetSecretValue` permission.

5. **"failed to parse secret JSON"**: The secret value must be a valid JSON object mapping key IDs to PEM-encoded public keys.

6. **"no public key found for kid"**: The JWT's `kid` header does not match any key ID in the secret. Check that the key ID in the JWT matches one of the keys in the secret.

7. **"token missing 'kid' header"**: JWTs must include a `kid` header when using AWS Secrets Manager keys.

8. **"cannot configure both cert and AWS Secrets Manager"**: The static `cert` and `awsSecretsManager` options are mutually exclusive. Remove one of them.

## Security Considerations

1. **Least Privilege**: Grant only `secretsmanager:GetSecretValue` permission, scoped to the specific secret ARN.

2. **Secret Encryption**: AWS Secrets Manager encrypts secrets at rest using KMS. Use a customer-managed KMS key for additional control.

3. **Refresh Interval**: Use a short refresh interval (e.g., 1-5 minutes) to pick up key rotations quickly. The default of 1 minute is appropriate for most use cases.

4. **Key Types**: Prefer Ed25519 (EdDSA) keys for new deployments. They are faster and produce smaller signatures than RSA.

5. **TLS**: Always use TLS for all communication to protect tokens in transit.

6. **Access Control**: Always configure access control policies to limit what authenticated clients can do.
