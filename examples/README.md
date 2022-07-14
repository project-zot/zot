
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
* [Sync](#sync)


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

Glob patterns can also be used as repository paths.

Authorization is granted based on the longest path matched.
For example repos2/repo repository will match both "**" and "repos2/repo" keys,
in such case repos2/repo policy will be used because it's longer.

Because we use longest path matching we need a way to specify a global policy to override all the other policies.
For example, we can specify a global policy with "**" (will match all repos), but any other policy will overwrite it,
because it will be longer. So that's why we have the option to specify an adminPolicy.

Basically '**' means repositories not matched by any other per-repository policy.

create/update/delete can not be used without 'read' action, make sure read is always included in policies!

```
"accessControl": {
    "**": {                                                    # matches all repos (which are not matched by any other per-repository policy)
      "policies": [                                            # user based policies
        {
          "users": ["charlie"],
          "actions": ["read", "create", "update"]
        }
      ],
      "defaultPolicy": ["read", "create"],                     # default policy which is applied for authenticated users, other than "charlie"=> so these users can read/create repositories
      "anonymousPolicy": ["read]                               # anonymous policy which is applied for unauthenticated users => so they can read repositories
    },
    "tmp/**": {                                                # matches all repos under tmp/ recursively
      "defaultPolicy": ["read", "create", "update"]            # so all users have read/create/update on all repos under tmp/ eg: tmp/infra/repo
    },
    "infra/*": {                                               # matches all repos directly under infra/ (not recursively)
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
    "repos2/repo": {                                           # matches only repos2/repo repository
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
    "adminPolicy": {                                            # global admin policy (overrides per-repo policy)
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

- Config file: 

```
    "storage": {
        "rootDirectory": "/tmp/zot",  # local path used to store dedupe cache database
        "dedupe": true,
        "storageDriver": {
            "name": "s3",
            "rootdirectory": "/zot",  # this is a prefix that is applied to all S3 keys to allow you to segment data in your bucket if necessary.
            "region": "us-east-2",
            "bucket": "zot-storage",
            "secure": true,
            "skipverify": false,
            "accesskey": "<YOUR_ACCESS_KEY_ID>",
            "secretkey": "<YOUR_SECRET_ACCESS_KEY>"
        }
```

There are multiple ways to specify S3 credentials besides config file:

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



## Sync

Enable and configure sync with:

```
		"sync": {
```

Configure credentials for upstream registries:

```
			"credentialsFile": "./examples/sync-auth-filepath.json",
```

Configure each registry sync:

```
			"registries": [{
				"urls": ["https://registry1:5000"],
				"onDemand": false,                  # pull any image which the local registry doesn't have
				"pollInterval": "6h",               # polling interval, if not set then periodically polling will not run
				"tlsVerify": true,                  # whether or not to verify tls (default is true)
				"certDir": "/home/user/certs",      # use certificates at certDir path, if not specified then use the default certs dir
				"maxRetries": 5,                    # maxRetries in case of temporary errors (default: no retries)
				"retryDelay": "10m",                # delay between retries, retry options are applied for both on demand and periodically sync and retryDelay is mandatory when using maxRetries.
				"onlySigned": true,                 # sync only signed images (either notary or cosign)
				"content":[                         # which content to periodically pull, also it's used for filtering ondemand images, if not set then periodically polling will not run
					{
						"prefix":"/repo1/repo",         # pull image repo1/repo
						"tags":{                        # filter by tags
							"regex":"4.*",                # filter tags by regex
							"semver":true                 # filter tags by semver compliance
						}
					},
					{
						"prefix":"/repo2/repo*"         # pull all images that matches repo2/repo.*
					},
					{
						"prefix":"/repo3/**"            # pull all images under repo3/ (matches recursively all repos under repo3/)
					},
          {
            "prefix":"/repo1/repo",          # pull /repo1/repo
            "destination":"/localrepo",      # put /repo1/repo under /localrepo
            "stripPrefix":true               # strip the path specified in "prefix", if true resulting /localpath, if false resulting /localrepo/repo1/repo"
          }
          {
            "prefix":"/repo1/**",           # pull all images under repo1/ (matches recursively all repos under repo1/)
            "destination":"/localrepo",     # put all images found under /localrepo.
            "stripPrefix":true              # strip the path specified in "prefix" until meta-characters like "**". If we match /repo1/repo the local repo will be /localrepo/repo.
          }
				]
			},
			{
				"urls": ["https://registry2:5000", "https://registry3:5000"], // specify multiple URLs in case first encounters an error
				"pollInterval": "12h",
				"tlsVerify": false,
				"onDemand": false,
				"content":[
					{
						"prefix":"/repo2",
						"tags":{
							"semver":true
						}
					}
				]
			},
			{
				"urls": ["https://docker.io/library"],
				"onDemand": true,                     # doesn't have content, don't periodically pull, pull just on demand.
				"tlsVerify": true,
				"maxRetries": 3,                      
				"retryDelay": "15m"
			}
		]
		}
```

Prefixes can be strings that exactly match repositories or they can be [glob](https://en.wikipedia.org/wiki/Glob_(programming)) patterns.
