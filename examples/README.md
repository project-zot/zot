
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

- [Configuration Parameters](#configuration-parameters)
  - [Network](#network)
  - [Storage](#storage)
  - [Authentication](#authentication)
    - [TLS Mutual Authentication](#tls-mutual-authentication)
    - [Passphrase Authentication](#passphrase-authentication)
      - [Authentication Failures](#authentication-failures)
      - [API keys](#api-keys)
  - [Identity-based Authorization](#identity-based-authorization)
  - [Logging](#logging)
  - [Metrics](#metrics)
  - [Storage Drivers](#storage-drivers)
    - [Specifying S3 credentials](#specifying-s3-credentials)
  - [Sync](#sync)


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

Orphan blobs are removed if they are older than gcDelay.

```
        "gcDelay": "2h"
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

## Retention

You can define tag retention rules that govern how many tags of a given repository to retain, or for how long to retain certain tags.

There are 4 possible rules for tags:

mostRecentlyPushedCount: x - top x most recently pushed tags
mostRecentlyPulledCount: x - top x most recently pulled tags
pulledWithin: x hours - tags pulled in the last x hours
pushedWithin: x hours - tags pushed in the last x hours

If ANY of these rules are met by a tag, then it will be retained, in other words there is an OR logic between them

repositories uses glob patterns
tag patterns uses regex

```
        "retention": {
            "dryRun": false,  // if enabled will just log the retain action without actually removing
            "delay": "24h",   // is applied on untagged and referrers, will remove them only if they are older than 24h
            "policies": [     // a repo will match a policy if it matches any repoNames[] glob pattern, it will select the first policy it can matches
                {
                    "repositories": ["infra/*", "prod/*"], // patterns to match
                    "deleteReferrers": false,           // delete manifests with missing Subject (default is false)
                    "deleteUntagged": true,             // delete untagged manifests (default is true)
                    "KeepTags": [{                      // same as repo, the first pattern(this time regex) matched is the policy applied
                        "patterns": ["v2.*", ".*-prod"] // if there is no rule then the default is to retain always, this tagRetention will retain all tags matching the regexes in the patterns list.
                    },
                    {
                        "patterns": ["v3.*", ".*-prod"], 
                        "pulledWithin": "168h"          // will keep v3.* and .*-prod tags that are pulled within last 168h
                    }]
                },                                      // all tags under infra/* and prod/* will be removed! because they don't match any retention policy
                {
                    "repositories": ["tmp/**"],            // matches recursively all repos under tmp/
                    "deleteReferrers": true,
                    "deleteUntagged": true,
                    "KeepTags": [{                      // will retain all tags starting with v1 and pulled within the last 168h
                        "patterns": ["v1.*"],           // all the other tags will be removed
                        "pulledWithin": "168h",      
                        "pushedWithin": "168h"
                    }]
                },
                {
                    "repositories": ["**"],
                    "deleteReferrers": true,
                    "deleteUntagged": true,
                    "keepTags": [{
                        "mostRecentlyPushedCount": 10,    // top 10 recently pushed tags
                        "mostRecentlyPulledCount": 10,    // top 10 recently pulled tags
                        "pulledWithin": "720h",
                        "pushedWithin": "720h"
                    }]
                }
            ]
        }
```

If a repo doesn't match any policy, then that repo and all its tags are retained. (default is to not delete anything)
If keepTags is empty, then all tags are retained (default is to retain all tags)
If we have at least one tagRetention policy in the tagRetention list then all tags that don't match at least one of them will be removed!

For safety purpose you can have a default policy as the last policy in list, all tags that don't match the above policies will be retained by this one:
```
                    "keepTags": [
                      {                               
                        "patterns": [".*"]           // will retain all tags
                      }
                    }]
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
        "credentialsFile": "config-ldap-credentials.json",
        "skipVerify":false,
        "subtreeSearch":true
      },
```

NOTE: When both htpasswd and LDAP configuration are specified, LDAP authentication is given preference.
NOTE: The separate file for storing DN and password credentials must be created. You can see example in `examples/config-ldap-credentials.json` file.

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

### OpenID/OAuth2 social login

zot supports several openID/OAuth2 providers:
 - google
 - github
 - gitlab
 - dex

zot can be configured to use the above providers with:
```
{
  "http": {
    "address": "127.0.0.1",
    "port": "8080",
    "auth": {
      "openid": {
        "providers": {
          "github": {
            "clientid": <client_id>,
            "clientsecret": <client_secret>,
            "scopes": ["read:org", "user", "repo"]
          },
          "google": {
            "issuer": "https://accounts.google.com",
            "clientid": <client_id>,
            "clientsecret": <client_secret>,
            "scopes": ["openid", "email"]
          },
          "gitlab": {
            "issuer": "https://gitlab.com",
            "clientid": <client_id>,
            "clientsecret": <client_secret>,
            "scopes": ["openid", "read_api", "read_user", "profile", "email"]
          }
        }
      }
    }
  }
```

To login with either provider use http://127.0.0.1:8080/zot/auth/login?provider=\<provider\>&callback_ui=http://127.0.0.1:8080/home
for example to login with github use http://127.0.0.1:8080/zot/auth/login?provider=github&callback_ui=http://127.0.0.1:8080/home

callback_ui query parameter is used by zot to redirect to UI after a successful openid/oauth2 authentication

The callback url which should be used when making oauth2 provider setup is http://127.0.0.1:8080/zot/auth/callback/\<provider\>
for example github callback url would be http://127.0.0.1:8080/zot/auth/callback/github

If network policy doesn't allow inbound connections, this callback wont work!

dex is an identity service that uses OpenID Connect to drive authentication for other apps https://github.com/dexidp/dex
To setup dex service see https://dexidp.io/docs/getting-started/

To configure zot as a client in dex (assuming zot is hosted at 127.0.0.1:8080), we need to configure dex with:

```
staticClients:
  - id: zot-client
    redirectURIs:
      - 'http://127.0.0.1:8080/zot/auth/callback/oidc'
    name: 'zot'
    secret: ZXhhbXBsZS1hcHAtc2VjcmV0
```

zot can be configured to use dex with:

```
  "http": {
    "auth": {
      "openid": {
        "providers": {
          "oidc": {
            "name": "Corporate SSO",
            "clientid": "zot-client",
            "clientsecret": "ZXhhbXBsZS1hcHAtc2VjcmV0",
            "keypath": "",
            "issuer": "http://127.0.0.1:5556/dex",
            "scopes": ["openid", "profile", "email", "groups"]
          }
        }
      }
    }
  }
```

To login using openid dex provider use http://127.0.0.1:8080/zot/auth/login?provider=oidc

NOTE: Social login is not supported by command line tools, or other software responsible for pushing/pulling
images to/from zot.
Given this limitation, if openif authentication is enabled in the configuration, API keys are also enabled
implicitly, as a viable alternative authentication method for pushing and pulling container images.

### OpenID/OAuth2 social login behind a proxy/load balancer

In the case of running zot with openid enabled behind a proxy/load balancer http.externalUrl should be provided.

```
  "http": {
    "address": "0.0.0.0",
    "port": "8080",
    "externalUrl: "https://zot.example.com",
    "auth": {
      "openid": {
        "providers": {
          "github": {
            "clientid": <client_id>,
            "clientsecret": <client_secret>,
            "scopes": ["read:org", "user", "repo"]
          }
        }
      }
    }
  }
```
This config value will be used by oauth2/openid clients to redirect back to zot.

### Session based login

Whenever a user logs in zot using any of the auth options available(basic auth/openid) zot will set a 'session' cookie on its response.
Using that cookie on subsequent calls will authenticate them, asumming the cookie didn't expire.

In case of using filesystem storage sessions are saved in zot's root directory.
In case of using cloud storage sessions are saved in memory.

#### API keys

zot allows authentication for REST API calls using your API key as an alternative to your password.
The user can create or revoke his API keys after he has already authenticated using a different authentication mechanism.
An API key is shown to the user only when it is created. It can not be retrieved from zot with any other call.
An API key has the same permissions as the user who generated it.

Below are several use cases where API keys offer advantages:

- OpenID/OAuth2 social login is not supported by command-line tools or other such clients. In this case, the user
can login to zot using OpenID/OAuth2 and generate API keys to use later when pushing and pulling images.
- In cases where LDAP authentication is used and the user has scripts pushing or pulling images, he will probably not
want to store his LDAP username and password in a shared environment where there is a chance they are compromised.
If he generates and uses an API key instead, the security impact of that key being compromised is limited to zot,
the other services he accesses based on LDAP would not be affected.

To activate API keys use:

```
  "http": {
    "auth": {
      "apikey": true
    }
  }
```

##### How to create an API Key

Create an API key for the current user using the REST API

**Usage**: POST /zot/auth/apikey

**Produces**: application/json

**Sample input**:

```
POST /zot/auth/apikey
Body: {"label": "git", "scopes": ["repo1", "repo2"], "expirationDate": "2023-08-28T17:10:05+03:00"}'
```

The time format of expirationDate is RFC1123Z.

**Example cURL without expiration date**

```bash
curl -u user:password -X POST http://localhost:8080/zot/auth/apikey -d '{"label": "git", "scopes": ["repo1", "repo2"]}'
```

**Sample output**:

```json
{
  "createdAt": "2023-05-05T15:39:28.420926+03:00",
  "expirationDate": "0001-01-01T00:00:00Z",
  "isExpired": false,
  "creatorUa": "curl/7.68.0",
  "generatedBy": "manual",
  "lastUsed": "0001-01-01T00:00:00Z",
  "label": "git",
  "scopes": [
    "repo1",
    "repo2"
  ],
  "uuid": "46a45ce7-5d92-498a-a9cb-9654b1da3da1",
  "apiKey": "zak_e77bcb9e9f634f1581756abbf9ecd269"
}
```

**Example cURL with expiration date**

```bash
curl -u user:password -X POST http://localhost:8080/zot/auth/apikey -d '{"label": "myAPIKEY", "expirationDate": "2023-08-28T17:10:05+03:00"}'
```

**Sample output**:

```json
{
  "createdAt":"2023-08-28T17:09:59.2603515+03:00",
  "expirationDate":"2023-08-28T17:10:05+03:00",
  "isExpired":false,
  "creatorUa":"curl/7.68.0",
  "generatedBy":"manual",
  "lastUsed":"0001-01-01T00:00:00Z",
  "label":"myAPIKEY",
  "scopes":null,
  "uuid":"c931e635-a80d-4b52-b035-6b57be5f6e74",
  "apiKey":"zak_ac55a8693d6b4370a2003fa9e10b3682"
}
```

##### How to get list of API Keys

Get list of API keys for the current user using the REST API

**Usage**: GET /zot/auth/apikey

**Produces**: application/json

**Example cURL**

```bash
curl -u user:password -X GET http://localhost:8080/auth/apikey 
```

**Sample output**:

```json
{
  "apiKeys": [
    {
      "createdAt": "2023-05-05T15:39:28.420926+03:00",
      "expirationDate": "0001-01-01T00:00:00Z",
      "isExpired": true,
      "creatorUa": "curl/7.68.0",
      "generatedBy": "manual",
      "lastUsed": "0001-01-01T00:00:00Z",
      "label": "git",
      "scopes": [
        "repo1",
        "repo2"
      ],
      "uuid": "46a45ce7-5d92-498a-a9cb-9654b1da3da1"
    },
    {
      "createdAt": "2023-08-11T14:43:00.6459729+03:00",
      "expirationDate": "2023-08-17T18:24:05+03:00",
      "isExpired": false,
      "creatorUa": "curl/7.68.0",
      "generatedBy": "manual",
      "lastUsed": "2023-08-11T14:43:47.5559998+03:00",
      "label": "myAPIKEY",
      "scopes": null,
      "uuid": "294abf69-b62f-4e58-b214-dad2aec0bc52"
    }
  ]
}
```


##### How to use API Keys

**Using API keys with cURL**

```bash
curl -u user:zak_e77bcb9e9f634f1581756abbf9ecd269 http://localhost:8080/v2/_catalog
```

Other command line tools will similarly accept the API key instead of a password.

##### How to revoke an API Key

How to revoke an API key for the current user

**Usage**: DELETE /zot/auth/apikey?id=$uuid

**Produces**: application/json

**Example cURL**

```bash
curl -u user:password -X DELETE http://localhost:8080/zot/auth/apikey?id=46a45ce7-5d92-498a-a9cb-9654b1da3da1
```

#### Authentication Failures

Should authentication fail, to prevent automated attacks, a delayed response can be configured with:

```
  "http": {
    "auth": {
      "failDelay": 5
    }
  }
```

## Identity-based Authorization

Allowing actions on one or more repository paths can be tied to user
identities. Two additional per-repository policies can be specified for identities not in the whitelist:

- anonymousPolicy - applied for unathenticated users.
- defaultPolicy - applied for authenticated users.

Furthermore, a global admin policy can also be
specified which can override per-repository policies.

Glob patterns can also be used as repository paths.

Authorization is granted based on the longest path matched.
For example repos2/repo repository will match both "**" and "repos2/repo" keys,
in such case repos2/repo policy will be used because it's longer.

Because we use longest path matching we need a way to specify a global policy to override all the other policies.
For example, we can specify a global policy with "**" (will match all repos), but any other policy will overwrite it,
because it will be longer. So that's why we have the option to specify an adminPolicy.

Basically '**' means repositories not matched by any other per-repository policy.

Method-based action list:

- "read" - list/pull images
- "create" - push images (needs "read")
- "update" - overwrite tags (needs "read" and "create")
- "delete" - delete images (needs "read")

Behaviour-based action list

- "detectManifestCollision" - delete manifest by digest will throw an error if multiple manifests have the same digest (needs "read" and "delete")


```json
"accessControl": {
  "groups": {                                                  # reusable groups of users
    "group1": {
      "users": ["jack", "john", "jane", "ana"]
    },
    "group2": {
      "users": ["alice", "mike", "jim"]
    }
  },
  "repositories": {                                            # per-repository policies
    "**": {                                                    # matches all repos (which are not matched by any other per-repository policy)
      "policies": [                                            # user based policies
        {
          "users": ["charlie"],
          "actions": ["read", "create", "update"]
        }
      ],
      "defaultPolicy": ["read", "create", "delete", "detectManifestCollision"], # default policy which is applied for authenticated users, other than "charlie"=> so these users can read/create/delete repositories and also can detect manifests collision.
      "anonymousPolicy": ["read"]                               # anonymous policy which is applied for unauthenticated users => so they can read repositories
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
              "groups": ["group1"],
              "actions": ["read", "create"]
          },
          {
              "users": ["mallory"],
              "actions": ["create", "read"]
          }
        ],
        "defaultPolicy": ["read"]
    }
  },
  "adminPolicy": {                                             # global admin policy (overrides per-repo policy)
      "users": ["admin"],
      "actions": ["read", "create", "update", "delete"]
  }
}
```

#### Scheduler Workers

The number of workers for the task scheduler has the default value of runtime.NumCPU()*4, and it is configurable with:

```
 "scheduler": {
        "numWorkers": 3
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
- [s3 config](https://github.com/docker/docker.github.io/blob/master/registry/storage-drivers/s3.md): A driver storing objects in an Amazon Simple Storage Service (S3) bucket.

For an s3 zot configuration with multiple storage drivers see: [s3-config](config-s3.json).

zot also supports different storage drivers for each subpath.

### S3 permissions scopes

The following AWS policy is required by zot for push and pull. Make sure to replace S3_BUCKET_NAME with the name of your bucket.

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetBucketLocation",
        "s3:ListBucketMultipartUploads"
      ],
      "Resource": "arn:aws:s3:::S3_BUCKET_NAME"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:ListMultipartUploadParts",
        "s3:AbortMultipartUpload"
      ],
      "Resource": "arn:aws:s3:::S3_BUCKET_NAME/*"
    }
  ]
}

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

## Cache drivers

zot supports two types of cache drivers: boltdb which is local and dynamodb which is remote.
They are used when dedupe is enabled to store duplicate blobs.

### BoltDB

Like s3 configuration, if you don't specify a cache driver it will default to 'boltdb' and it wil be stored in zot's root directory or subpath root directory
```
  "storage": {
    "rootDirectory": "/tmp/zot",
    "dedupe": true
  }
```
boltdb can be found at /tmp/zot/cache.db

### DynamoDB

To set up a zot with dedupe enabled and dynamodb as a cache driver, "cacheDriver" field should be included under 'storage'
```
    "storage": {
        "rootDirectory": "/tmp/zot",
        "dedupe": true,
        "remoteCache": true,
        "cacheDriver": {
            "name": "dynamodb",  // driver name
            "endpoint": "http://localhost:4566", // aws endpoint
            "region": "us-east-2" // aws region
            "cacheTablename": "ZotBlobTable" // table used to store deduped blobs

        }
    },
```
Like s3 configuration AWS GO SDK will load additional config and credentials values from the environment variables, shared credentials, and shared configuration files

Additionally if search extension is enabled, additional parameters are needed:

```
        "cacheDriver": {
            "name": "dynamodb",
            "endpoint": "http://localhost:4566",
            "region": "us-east-2",
            "cacheTablename": "ZotBlobTable",
            // used by search extensions
            "repoMetaTablename": "ZotRepoMetadataTable",
            "manifestDataTablename": "ZotManifestDataTable",
            "userDataTablename": "ZotUserDataTable",
            "versionTablename": "ZotVersion"
        }
```

### DynamoDB permission scopes
The following AWS policy is required by zot for caching blobs. Make sure to replace DYNAMODB_TABLE with the name of your table which in our case is the value of "cacheTablename" (ZotBlobTable)

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:CreateTable",
        "dynamodb:GetItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem"
      ],
      "Resource": "arn:aws:dynamodb:*:*:table/DYNAMODB_TABLE"
    }
  ]
}

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
				"urls": ["https://index.docker.io"],
				"onDemand": true,                     # doesn't have content, don't periodically pull, pull just on demand.
				"tlsVerify": true,
				"maxRetries": 3,                      
				"retryDelay": "15m"
			}
		]
		}
```

Prefixes can be strings that exactly match repositories or they can be [glob](https://en.wikipedia.org/wiki/Glob_(programming)) patterns.
