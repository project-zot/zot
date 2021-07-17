
The behavior of _zot_ registry is controlled via its configuration file, which
can either be a JSON (used in details below) or YAML file.

```
zot serve <config-file>

```

A candidate configuration file can be verified via:

```
zot verify <config-file>

```

Examples of working configurations for various use cases are available [here](../examples/)

# Configuration Parameters

* [Network](#network)
* [Storage](#storage)
* [Authentication](#authentication)
* [Identity-based Authorization](#identity-based-authorization)
* [Logging](#logging)
* [Metrics](#metrics)


## Network

Configure network params with:
```
"http": {
```

Configure address and port to listen on with:
```
        "address": "127.0.0.1",
        "port": "5000",
```

Additionally, TLS configuration can be specified with:

```
        "tls": {
            "cert":"test/data/server.cert",
            "key":"test/data/server.key"
        },
```

The registry can be deployed as a read-only service with:

```
        "ReadOnly": false
    },
```

## Storage

Configure storage with:

```
"storage": {
```

Configure storage root directory with:

```
        "rootDirectory": "/tmp/zot",
```

Often, container images have shared layers and blobs and for filesystems that
support hard links, inline deduplication can be enabled with:

```
        "dedupe": true,
```

When an image is deleted (either by tag or reference), orphaned blobs can lead
to wasted storage, and background garbage collection can be enabled with:

```
        "gc": true,
```

It is also possible to store and serve images from multiple filesystems with
their own repository paths, dedupe and garbage collection settings with:

```
        "subPaths": {
            "/a": {
                "rootDirectory": "/tmp/zot1",
                "dedupe": true,
                "gc": true
            },
            "/b": {
                "rootDirectory": "/tmp/zot2",
                "dedupe": true
            },
            "/c": {
                "rootDirectory": "/tmp/zot3",
                "dedupe": false
            }
        }
    },
```

## Authentication

TLS mutual authentication and passphrase-based authentication are supported.

### TLS Mutual Authentication

Apart from the server cert and key specified under
[network configuration](#network), specifying the _cacert_ field enables TLS mutual
authentication:

```
"http": {
    "tls": {
      "cert":"test/data/server.cert",
      "key":"test/data/server.key",
      "cacert":"test/data/cacert.cert"
    },
```

### Passphrase Authentication

**Local authentication** is supported via htpasswd file with:

```
  "http": {
    "auth": {
      "htpasswd": {
        "path": "test/data/htpasswd"
      },
```

**LDAP authentication** can be configured with:

```
  "http": {
    "auth": {
      "ldap": {
        "address":"ldap.example.org",
        "port":389,
        "startTLS":false,
        "baseDN":"ou=Users,dc=example,dc=org",
        "userAttribute":"uid",
        "bindDN":"cn=ldap-searcher,ou=Users,dc=example,dc=org",
        "bindPassword":"ldap-searcher-password",
        "skipVerify":false,
        "subtreeSearch":true
      },
```

NOTE: When both htpasswd and LDAP configuration are specified, LDAP authentication is given preference.

**OAuth2 authentication** (client credentials grant type) support via _Bearer Token_ configured with:

```
  "http": {
    "auth": {
      "bearer": {
        "realm": "https://auth.myreg.io/auth/token",
        "service": "myauth",
        "cert": "/etc/zot/auth.crt"
      }
```

#### Authentication Failures

Should authentication fail, to prevent automated attacks, a delayed response can be configured with:

```
  "http": {
    "auth": {
      "failDelay": 5
```

## Identity-based Authorization

Allowing actions on one or more repository paths can be tied to user
identities. An additional per-repository default policy can be specified for
identities not in the whitelist. Furthermore, a global admin policy can also be
specified which can override per-repository policies.

```
"accessControl": {
    "repos1/repo": {
        "policies": [
        {
            "users": ["alice", "bob"],
            "actions": ["create", "read", "update", "delete"]
        },
        {
            "users": ["mallory"],
            "actions": ["create", "read"]
        }
        ],
        "defaultPolicy": ["read"]
    },
    "repos2/repo": {
        "policies": [
        {
            "users": ["bob"],
            "actions": ["read", "create"]
        },
        {
            "users": ["mallory"],
            "actions": ["create", "read"]
        }
        ],
        "defaultPolicy": ["read"]
    },
    "adminPolicy": {
        "users": ["admin"],
        "actions": ["read", "create", "update", "delete"]
    }
}
```

## Logging

Enable and configure logging with:

```
"log":{
```

Set log level with:

```
    "level":"debug",
```

Set output file (default is _stdout_) with:

```
    "output":"/tmp/zot.log",
```

Enable audit logs and set output file with:

```
    "audit": "/tmp/zot-audit.log"
  }
```

## Metrics

Enable and configure metrics with:

```
"metrics":{
    "enable":"true",

```

Set server path on which metrics will be exposed:

```
    "prometheus": {
      "path": "/metrics"
    }
}
```

In order to test the Metrics feature locally in a [Kind](https://kind.sigs.k8s.io/) cluster, folow [this guide](metrics/README.md).

## Storage Drivers

Beside filesystem storage backend, zot also supports S3 storage backend, check below url to see how to configure it:
- [s3](https://github.com/docker/docker.github.io/blob/master/registry/storage-drivers/s3.md): A driver storing objects in an Amazon Simple Storage Service (S3) bucket.

For an s3 zot configuration with multiple storage drivers see: [s3-config](config-s3.json).

zot also supports different storage drivers for each subpath.

### Specifying S3 credentials

There are multiple ways to specify S3 credentials:

- Config file: 

```
        "storageDriver": {
            "name": "s3",
            "region": "us-east-2",
            "bucket": "zot-storage",
            "secure": true,
            "skipverify": false,
            "accesskey": "<YOUR_ACCESS_KEY_ID>",
            "secretkey": "<YOUR_SECRET_ACCESS_KEY>"
        }
```

- Environment variables:

SDK looks for credentials in the following environment variables:

```
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
    AWS_SESSION_TOKEN (optional)
```

- Credentials file:

A credential file is a plaintext file that contains your access keys. The file must be on the same machine on which you’re running your application. The file must be named credentials and located in the .aws/ folder in your home directory.

```
    [default]
    aws_access_key_id = <YOUR_DEFAULT_ACCESS_KEY_ID>
    aws_secret_access_key = <YOUR_DEFAULT_SECRET_ACCESS_KEY>

    [test-account]
    aws_access_key_id = <YOUR_TEST_ACCESS_KEY_ID>
    aws_secret_access_key = <YOUR_TEST_SECRET_ACCESS_KEY>

    [prod-account]
    ; work profile
    aws_access_key_id = <YOUR_PROD_ACCESS_KEY_ID>
    aws_secret_access_key = <YOUR_PROD_SECRET_ACCESS_KEY>
```

The [default] heading defines credentials for the default profile, which the SDK will use unless you configure it to use another profile.

To specify a profile use AWS_PROFILE environment variable:

```
AWS_PROFILE=test-account
```

For more details see https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials



