
The behavior of _zot_ registry is controlled via its configuration file, which
can either be a JSON (used in details below) or YAML file.

```
zot serve <config-file>

```

A candidate configuration file can be verified via:

```
zot verify <config-file>

```

The complete machine-readable configuration reference can be generated from the
same binary:

```
zot schema > zot-config-schema.json

```

The generated schema is JSON Schema draft 7. It is built from the same
configuration model used by `zot verify`, so it is the preferred reference for
editor integration, CI validation, and checking accepted field names.

Examples of working configurations for various use cases are available [here](../examples/)

# Configuration Parameters

- [Configuration Parameters](#configuration-parameters)
  - [Generated JSON Schema](#generated-json-schema)
  - [Top-level Configuration Map](#top-level-configuration-map)
  - [Network](#network)
  - [Storage](#storage)
    - [Fast restart](#fast-restart)
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
  - [Search and CVE scanning (Trivy)](#search-and-cve-scanning-trivy)

## Generated JSON Schema

Use `zot schema` when you need a complete field-level reference instead of a
scenario-specific example file.

```
zot schema > zot-config-schema.json
zot verify config.json

```

The schema output includes nested options for storage drivers, authentication,
authorization, extensions, sync, events, retention, and clustering. It also
includes supported field aliases where the config loader accepts them.

## Top-level Configuration Map

| Key | Type | Purpose |
| --- | --- | --- |
| `distSpecVersion` | string | Distribution spec version declared by the config. zot warns if it differs from the supported version and then uses the supported version. |
| `storage` | object | Registry storage root, dedupe, garbage collection, retention, storage drivers, cache drivers, and repository subpaths. |
| `http` | object | Listener address and port, TLS, authentication, authorization, CORS, rate limits, realm, and client compatibility settings. |
| `log` | object | Log level, primary log output, and audit log output. |
| `extensions` | object | Optional sync, search, UI, metrics, scrub, lint, image trust, API key, management, and event-recorder settings. |
| `scheduler` | object | Background task scheduler settings such as worker count. |
| `cluster` | object | Scale-out members, cluster hash key, and cluster TLS settings. |
| `goVersion`, `commit`, `releaseTag`, `binaryType` | string | Build metadata fields populated by zot; they are not normally set in user configuration files. |

The sections below describe the most common settings and point to working
example files for complete configurations.

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

To limit the maximum number of repositories that can be created, set:

```
        "maxRepos": 10
```

When the limit is reached, pushes that would create a new repository are
rejected with HTTP 429. Pushes to existing repositories are always allowed.
Setting maxRepos to 0 or omitting it disables enforcement.

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

### Fast restart

On large registries (for example a 1TB+ S3 backend with many repos), the
startup walk that reconciles metaDB with the current storage can dominate
restart time. Setting `fastRestart` lets zot skip that walk when the same
binary is restarted with the same storage config. After a successful walk,
zot stamps metaDB with the running binary's identity plus a fingerprint of
the storage config, so that the next startup, if the stamp matches, may skip
the walk. Any binary upgrade or storage configuration changes (for example,
`dedupe`/`rootDirectory`/`subPaths`) invalidates the stamp and forces a full
reparse.

Fast restart is off by default. The trade-off when enabling it is that
out-of-band changes to Zot's storage will not be detected and may cause
inconsistencies between the metaDB and storage. To enable it:

```json
    "storage": {
        "rootDirectory": "/var/lib/registry",
        "fastRestart": true
    }
```

`fastRestart` is a top-level storage setting; it is not honored under `subPaths`.

You can also force a full reparse with the `--force-reparse` flag to `zot serve`.

## Retention

You can define tag retention rules that govern how many tags of a given repository to retain, or for how long to retain certain tags.
You can also define `keepUntagged` rules for untagged manifests, including manifests cached by digest-only pull-through requests.

There are 4 possible rules for tags:

mostRecentlyPushedCount: x - top x most recently pushed tags
mostRecentlyPulledCount: x - top x most recently pulled tags
pulledWithin: x hours - tags pulled in the last x hours
pushedWithin: x hours - tags pushed in the last x hours

The same 4 rules can be used under `keepUntagged`; for digest-only cached content, pushed means cached locally at the descriptor's push timestamp.
Tagged and untagged manifests are evaluated separately, so counts in `keepTags` do not compete with counts in `keepUntagged`.
An empty `keepUntagged: {}` does not retain all untagged manifests; it is equivalent to omitting `keepUntagged`.
`keepUntagged` rules require the metadata database. If it is unavailable, zot ignores `keepUntagged` and uses the existing delay-based untagged cleanup.

If ANY of these rules are met by a tag or untagged manifest, then it will be retained, in other words there is an OR logic between them

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
                    }],
                    "keepUntagged": {                   // untagged manifests pulled or cached locally within the last 168h are retained
                        "pulledWithin": "168h",
                        "pushedWithin": "168h"
                    }
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
                    }],
                    "keepUntagged": {
                        "mostRecentlyPushedCount": 10,    // top 10 recently cached/pushed untagged manifests
                        "mostRecentlyPulledCount": 10,    // top 10 recently pulled untagged manifests
                        "pulledWithin": "720h",
                        "pushedWithin": "720h"
                    }
                }
            ]
        }
```

If a repo doesn't match any policy, then that repo and all its tags are retained. (default is to not delete anything)
If keepTags is empty, then all tags are retained (default is to retain all tags)
If we have at least one tagRetention policy in the tagRetention list then all tags that don't match at least one of them will be removed!
`deleteUntagged` remains the master switch for untagged manifests. When `deleteUntagged` is true and `keepUntagged` is configured, untagged manifests that fail `keepUntagged` rules still honor the configured retention delay before deletion. Without `keepUntagged`, untagged manifests keep the existing delay-based cleanup behavior.

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

By default, mTLS authentication extracts the client identity from the certificate's
Common Name (CN) field. You can configure alternative identity attributes and a fallback
chain using the `mtls` configuration under `auth`:

```
"http": {
    "auth": {
      "mtls": {
        "identityAttributes": ["CommonName", "Subject", "Email", "URI", "DNSName"],
        "uriSanPattern": "spiffe://example.org/workload/(.*)",
        "uriSanIndex": 0,
        "dnsSanIndex": 0,
        "emailSanIndex": 0
      }
    }
}
```

**Identity Attributes:**
- `CommonName` or `CN` - Extract identity from the certificate's Common Name (CN) field (default)
- `Subject` or `DN` - Extract identity from the full Subject Distinguished Name (DN)
- `Email` or `rfc822name` - Extract identity from Email SAN (Subject Alternative Name)
- `URI` or `URL` - Extract identity from URI SAN (Subject Alternative Name)
- `DNSName` or `DNS` - Extract identity from DNS SAN (Subject Alternative Name)

The `identityAttributes` array defines a fallback chain - if the first identity attribute fails to
extract an identity, the next identity attribute is tried, and so on. All identity attribute
names are case-insensitive.

**URI SAN Pattern:**
When using `URI` as an identity attribute, you can specify a regex pattern to extract
a specific part of the URI. For example, with SPIFFE certificates:
- URI: `spiffe://example.org/workload/testuser`
- Pattern: `spiffe://example.org/workload/(.*)`
- Extracted identity: `testuser`

If no pattern is specified, the full URI value is used as the identity.

**SAN Indexes:**
When multiple values exist in a SAN field (URI, DNS, or Email), you can specify
which one to use with the index fields (0-based). Default is 0 (first value).

**Example Configurations:**
- Basic mTLS with CommonName: `examples/config-mtls.json`
- SPIFFE with URI SAN pattern: `examples/config-mtls-spiffe.json`

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

When OIDC workload identity/federation uses Zot `/zot/auth/token` but the same deployment still needs this traditional bearer token service, configure the optional `upstreamTokenEndpoint` object. `upstreamTokenEndpoint.realm` points to the existing traditional bearer token service and `upstreamTokenEndpoint.service` is the upstream service value; Zot preserves the token request and rewrites only `service` before proxying requests that are not owned by local token backends. `upstreamTokenEndpoint.realm` must use HTTPS by default; plaintext HTTP requires `upstreamTokenEndpoint.allowInsecureHttp: true` and should only be used in controlled test environments.

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


To login with either provider use http://127.0.0.1:8080/zot/auth/login?provider=\<provider\>&callback_ui=/home
for example to login with github use http://127.0.0.1:8080/zot/auth/login?provider=github&callback_ui=/home

callback_ui query parameter is used by zot to redirect to UI after a successful openid/oauth2 authentication

By default, `callback_ui` must be a relative path (starting with `/`) to prevent open redirects.
If your UI runs on a different origin (e.g. different port during development), you can allowlist
absolute redirect origins via:

```
{
  "http": {
    "auth": {
      "openid": {
        "callbackAllowOrigins": ["http://127.0.0.1:3000"]
      }
    }
  }
}
```

The callback url which should be used when making oauth2 provider setup is http://127.0.0.1:8080/zot/auth/callback/\<provider\>
for example github callback url would be http://127.0.0.1:8080/zot/auth/callback/github

If network policy doesn't allow inbound connections, this callback wont work!

#### GitHub Teams in Access Control

When authenticating with the GitHub provider, if you include the `read:org` scope, zot will fetch both the user's Organization memberships and their Team memberships.
Team memberships are formatted as `<organization>/<team-slug>` and added to the user's groups. You can use these in your access control policies. For example, if a user belongs to the `Infra` team in the `myorg` organization, the group name will be `myorg/infra`.
Group strings preserve GitHub-provided `login`/`slug` casing (no lowercasing is applied), so policy group values must match that exact casing.

```json
{
  "accessControl": {
    "repositories": {
      "myorg/infrastructure/**": {
        "policies": [
          {
            "groups": ["myorg/infra"],
            "actions": ["read", "create", "update", "delete"]
          }
        ]
      }
    }
  }
}
```

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
            "scopes": ["openid", "profile", "email", "groups"],
            "claimMapping": {
              "username": "preferred_username",
              "groups": "groups"
            }
          }
        }
      }
    }
  }
```

To login using openid dex provider use http://127.0.0.1:8080/zot/auth/login?provider=oidc

`claimMapping.username` defaults to `email`, and `claimMapping.groups` defaults to `groups`.

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
    "externalUrl": "https://zot.example.com",
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

### OpenID/OAuth2 Social Login with Custom URLs (Self-Hosted Providers)

#### Use Cases
- GitHub Enterprise Server (on-premises GitHub)
- GitLab Self-Managed instances
- Custom corporate OAuth2/OIDC providers

When integrating zot with self-hosted OAuth2 providers like GitHub Enterprise Server, GitLab Self-Managed, 
or custom OIDC implementations, you must specify custom authentication and token endpoints since 
the default public endpoints won't work.

```
  "http": {
    "address": "0.0.0.0",
    "port": "8080",
    "externalUrl": "https://zot.example.com",
    "auth": {
      "openid": {
        "providers": {
          "github": {
            "clientid": <client_id>,
            "clientsecret": <client_secret>,
            "authurl": "https://github.company.com/login/oauth/authorize",     // Custom GHE authorization endpoint
            "tokenurl": "https://github.company.com/login/oauth/access_token", // Custom GHE token endpoint
            "scopes": ["read:org", "user", "repo"]
          }
        }
      }
    }
  }
```

Without `authurl`/`tokenurl`, zot assumes public GitHub.com endpoints.

### Session based login

Whenever a user logs in zot using any of the auth options available(basic auth/openid) zot will set a 'session' cookie on its response.
Using that cookie on subsequent calls will authenticate them, asumming the cookie didn't expire.

In case of using filesystem storage sessions are saved in zot's root directory.
In case of using cloud storage sessions are saved in memory.

Note: By default, the session driver config would be local for file system or in-memory. The session driver name for this is `local`. An example config is shown below, but the config can be omitted as it is a default.

```
    "auth": {
      "htpasswd": {
        "path": "test/data/htpasswd"
      },
      "sessionDriver": {
        "name": "local"
      }
    }
```

Note: This `sessionDriver` config is optional if a local session storage is desired.

#### Remote Session Storage Driver

Redis and Redis-compatible storage drivers can also be used for cases where session storage is required to be kept separately from zot or multiple zot instances need to share the session information.

This can be configured in the `auth` section of the configuration as shown below:

`sessionDriver`

```
    "auth": {
      "htpasswd": {
        "path": "test/data/htpasswd"
      },
      "sessionDriver": {
        "name": "redis",
        "url": "redis://localhost:6379",
        "keyprefix": "zotsession"
      }
    }
```

The `redis` driver configuration options are the same as those in the [Redis Cache Driver](#redis) section. If the `redis` session driver is being used along with a `redis` cache driver and both configurations point to the same Redis instance, there will be two independent connections used.

Note: The `redis` session driver cannot be specified along with configuration for the SessionKeysFile.

### Securing session based login

In order to secure session cookies used in session based authentication process you need to set the path to a file containg keys used to hash and encrypt the cookies:

`sessionKeysFile`

```
    "auth": {
      "htpasswd": {
        "path": "test/data/htpasswd"
      },
      "sessionKeysFile": "/home/user/keys",
      "apikey": true,
    }
```

```
user@host:~/zot$ cat ../keys  | jq
{
  "hashKey": "my-very-secret",
  "encryptKey": "another-secret"
}
```

- hashKey  -  used to authenticate the cookie value using HMAC. It is recommended to use a key with exactly 32 or 64 bytes. 
- encryptKey - this is optional, used to encrypt the cookie value. If set, the length must correspond to the block size of the encryption algorithm. For AES, used by default, valid lengths are 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.

If at least hashKey is not set zot will create a random one which on zot restarts it will invalidate all currently valid cookies and their sessions, requiring all users to login again.

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

##### Metrics access control

The `metrics` key inside `accessControl` controls access to the Prometheus scrape endpoint independently of repository policies. It supports two fields:

- `users` - list of named authenticated users allowed to scrape. Requires authentication (e.g. htpasswd) to be configured.
- `anonymousPolicy` - set to `["read"]` to allow unauthenticated access to the metrics endpoint when authentication is configured for other routes.

To restrict scraping to specific named users:

```
"accessControl": {
    "metrics": {
        "users": ["prometheus"]
    }
}
```

See [config-metrics-authz.json](config-metrics-authz.json) for a complete example combining htpasswd authentication with repository policies.

When authentication is configured and repositories have non-anonymous policies, `anonymousPolicy` on `metrics` allows unauthenticated scrapers to reach the metrics endpoint while keeping repository routes protected:

```
"http": {
    "auth": {
        "htpasswd": { "path": "test/data/htpasswd" }
    },
    "accessControl": {
        "metrics": {
            "anonymousPolicy": ["read"]
        },
        "repositories": {
            "**": { "defaultPolicy": ["read", "create"] }
        }
    }
}
```

See [config-metrics-authn-anonymous-access.json](config-metrics-authn-anonymous-access.json) for a complete example.

##### Conditional access on policies

Policy entries can carry an optional list of `conditions`: CEL boolean
expressions that must all evaluate to true for the entry to grant access.
This is the same pattern as conditional access in cloud IAM systems.

```
"policies": [{
  "users": ["alice"],
  "actions": ["read", "create", "update"],
  "conditions": [{
      "expression": "req.time < timestamp(\"2099-12-31T23:59:59Z\")",
      "message": "alice's access expires end of 2099"
    },
    {
      "expression": "req.referenceType == \"digest\"",
      "message": "prod pushes must use digest references"
    }
  ]
}]
```

Expressions evaluate against a `req` struct with the following fields:

| Path | Type | Description |
|---|---|---|
| `req.time` | timestamp | Current time as a CEL timestamp; compare with `timestamp("2099-12-31T23:59:59Z")`. |
| `req.method` | string | Raw HTTP method of the originating request (`"GET"`, `"PUT"`, ...). |
| `req.userAgent` | string | `User-Agent` header. |
| `req.action` | string | Abstract action being authorized: `"read"`, `"create"`, `"update"`, `"delete"`. Use this for action gating; `req.method` is the raw verb escape hatch. |
| `req.repository` | string | The requested repository, when known. |
| `req.reference` | string | Tag or digest, when the route has one. |
| `req.referenceType` | string | `"tag"`, `"digest"`, or `""` when the route has no reference. |
| `req.tag` | string | The tag, when reference is a tag. |
| `req.digest` | string | The digest, when reference is a digest. |
| `req.user.username` | string | Authenticated username. |
| `req.user.groups` | list&lt;string&gt; | Authenticated user's groups. |
| `req.auth.anonymous` | bool | Convenience for `req.user.username == ""`. |
| `req.auth.admin` | bool | True when the user matches the admin policy. |
| `req.client.ip` | string | TCP peer address from `RemoteAddr` (port stripped). Always trustworthy. |
| `req.client.forwardedFor` | list&lt;string&gt; | `X-Forwarded-For` chain, left to right. **Untrusted** — anyone can set the header. |
| `req.tls.enabled` | bool | Whether the request arrived over TLS at zot. |
| `req.tls.version` | string | TLS version: `"1.2"`, `"1.3"`, ... when applicable. |
| `req.claims` | map | Authn-time attribute bag, populated by the active authn flow (today: OIDC bearer fills it with the ID token claim set; other flows can feed this surface as they grow that capability). |

**Network gates.** `req.client.ip` is the TCP peer (the proxy, behind a
reverse proxy). `req.client.forwardedFor` is the raw header chain — useful
but spoofable, since any client can set it. The idiomatic pattern is to gate
on the chain only after asserting the TCP peer is your trusted proxy:

```
req.client.ip == "10.0.0.5" && req.client.forwardedFor[0].startsWith("192.0.2.")
```

**Deny messages.** When a condition evaluates to false, its `message` is
surfaced to the client in the 403 response body's error detail under the
`reason` key, and also logged for operator diagnosis. Internal lookup or
evaluation failures are *not* surfaced (the client just gets a generic deny)
to avoid leaking implementation issues.

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
- [s3 config](https://github.com/docker/docs/blob/d0aa0fe985c1dc3e3e4235966aacad7889de911f/content/manuals/build/cache/backends/s3.md): A driver storing objects in an Amazon Simple Storage Service (S3) bucket.

For an s3 zot configuration with multiple storage drivers see: [s3-config](config-s3.json).

zot also supports different storage drivers for each subpath.

### Azure Blob Storage

zot supports an Azure Blob Storage backend. For a full example see [azure config](config-azure.json).

The driver requires `accountname` and `container`, and selects how to authenticate via
`storageDriver.credentials.type`:

- `shared_key` — authenticate with a storage account key; set `accountkey`.
- `client_secret` — authenticate as an Entra (Azure AD) service principal; set `tenantid`,
  `clientid`, and `secret`.
- `default_credentials` — use the Azure SDK's `DefaultAzureCredential` chain, so **no secret
  is stored in the zot config**. It resolves a credential in order: Azure Workload Identity
  (federated token), Managed Identity, the `AZURE_*` environment variables, then Azure CLI
  login. This is the recommended option when zot runs on AKS or a self-managed cluster with
  the [Azure Workload Identity](https://azure.github.io/azure-workload-identity/) webhook —
  zot's pod receives a federated token and needs no stored credentials.

The example uses `default_credentials` (Workload Identity). `DefaultAzureCredential` works
wherever an ambient Azure identity is available — **not only on Azure**: any Kubernetes
cluster running the [azure-workload-identity](https://azure.github.io/azure-workload-identity/)
webhook can federate a managed identity to zot's ServiceAccount (the cluster's OIDC issuer
trusted by Entra), including **self-managed / non-Azure clusters**, and zot gets a token via
the WorkloadIdentityCredential — no secrets stored. For a plain standalone process with no
managed/federated identity, `default_credentials` falls back to the `AZURE_TENANT_ID` /
`AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` (or `AZURE_CLIENT_CERTIFICATE_PATH`) environment
variables or an `az login` session; otherwise use `shared_key` (with `accountkey`) or
`client_secret` (with a service principal).

Example (Workload Identity, secret-less):

```
    "storage": {
        "rootDirectory": "/tmp/zot",  # local path used to store dedupe cache database
        "dedupe": false,
        "storageDriver": {
            "name": "azure",
            "rootdirectory": "/zot",  # prefix applied to all blob names
            "accountname": "myazurestorageaccount",
            "container": "zot-storage",
            "credentials": { "type": "default_credentials" }
        }
    }
```

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
        "redirectBlobURL": true,
        "storageDriver": {
            "name": "s3",
            "rootdirectory": "/zot",  # this is a prefix that is applied to all S3 keys to allow you to segment data in your bucket if necessary.
            "region": "us-east-2",
            "bucket": "zot-storage",
            "forcepathstyle": true,
            "secure": true,
            "skipverify": false,
            "accesskey": "<YOUR_ACCESS_KEY_ID>",
            "secretkey": "<YOUR_SECRET_ACCESS_KEY>"
        }
    }
```

Blob pull redirects are disabled by default. With S3 or GCS storage, set `redirectBlobURL` to `true` under `storage` or under a `subPaths` entry to return a `307 Temporary Redirect` to the storage driver's signed URL after zot authorization. If the storage driver does not return a redirect URL, zot proxies the blob as before.

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
            // used for auth
            "userDataTablename": "ZotUserDataTable",
            "apiKeyTablename": "ZotApiKeyDataTable",
            // used by search extension
            "repoMetaTablename": "ZotRepoMetadataTable",
            "imageMetaTablename": "ZotImageMetaTable",
            "repoBlobsInfoTablename": "ZotRepoBlobsInfoTable",
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
        "dynamodb:DescribeTable",
        "dynamodb:DeleteTable",
        "dynamodb:Scan",
        "dynamodb:BatchGetItem",
        "dynamodb:GetItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem"
      ],
      "Resource": "arn:aws:dynamodb:*:*:table/DYNAMODB_TABLE"
    }
  ]
}

Note `dynamodb:DeleteTable` is used only in running the zot tests, should not be needed in production.

### Redis

Redis is an alternative to BoltDB (which cannot be shared by multiple zot instances) and DynamoDB (requires access to AWS).
Redis can be set up using a configuration similar to the one below:

```json
    "storage": {
        "rootDirectory": "/tmp/zot",
        "remoteCache": true,
        "cacheDriver": {
            "name": "redis",
            "url": "redis://localhost:6379",
            "keyprefix": "zot"
        }
    }
```

The "name" setting selects the Redis driver implementation.
The "keyprefix" is a string prepended to all Redis keys created by this zot instance.
The "url" setting points to the Redis server (or servers in the case of a Redis cluster).
More details on how this is parsed are available at:
- https://github.com/redis/go-redis/blob/v9.7.0/options.go#L247
- https://github.com/redis/go-redis/blob/v9.7.0/osscluster.go#L144

If the "url" setting is missing, the parameters need to be passed individually as keys in the same "cacheDriver" map.
The keys are the same as the attributes that would otherwise be included in the "url".
Note that at this time the library we import only supports "url" parsing in the case of a Redis single instance, or cluster configuration.
In the case of a Redis Sentinel setup, you would need to add each key manually in the "cacheDriver" map and make sure to specify
a "master_name" key, see https://github.com/redis/go-redis/blob/v9.7.0/universal.go#L240

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
				"certDir": "/home/user/certs",      # use certificates at certDir path similar to Docker's /etc/docker/certs.d., if not specified then use the default certs dir,
				"maxRetries": 5,                    # maxRetries in case of temporary errors (default: no retries)
				"retryDelay": "1s",                 # initial HTTP retry delay; mandatory when using maxRetries
				"maxRetryDelay": "30s",             # max HTTP retry backoff; optional, defaults to retryDelay (fixed interval). Set higher than retryDelay for exponential backoff.
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
				"retryDelay": "15m",                # initial HTTP retry delay; fixed 15m interval unless maxRetryDelay is set higher
				"maxRetryDelay": "15m"              # optional; omit or set equal to retryDelay for fixed interval (as here)
			}
		]
		}
```
Prefixes can be strings that exactly match repositories or they can be [glob](https://en.wikipedia.org/wiki/Glob_(programming)) patterns.

### Sync's certDir option

sync uses the same logic for reading cert directory as docker: https://docs.docker.com/engine/security/certificates/#understand-the-configuration
sync can also read the certificates directly under certDir:
 - ca.crt - public pem cert of registry. Root CA that signed the registry certificate, in PEM.
 - client.cert - public pem cert for client (mTLS)
 - client.key - public key cert for client (mTLS)

### Sync's credentials

Besides sync-auth.json file, zot also reads and uses docker credentials by default: https://docs.docker.com/reference/cli/docker/login/#description

## Search and CVE scanning (Trivy)

The `search` extension can include a `cve` section so zot downloads the [Trivy](https://github.com/aquasecurity/trivy) vulnerability database and exposes CVE data via the search API (for example GraphQL).

A minimal configuration only sets how often the DB is refreshed; zot applies defaults for Trivy DB locations and severity selection:

- [config-cve.json](config-cve.json) — `updateInterval` only; defaults are applied for the Trivy DB, Java DB (for language packages), and `vulnSeveritySources`.

To set those options explicitly (for example to mirror standalone Trivy’s `--vuln-severity-source` behavior), use a `trivy` object under `cve`:

- [config-cve-trivy.json](config-cve-trivy.json) — shows optional `dbRepository`, `javaDBRepository`, `vulnSeveritySources`, and `sbom`.

`vulnSeveritySources` is a list of source names in priority order (for example `auto`, `nvd`, or vendor IDs such as `redhat`, `alpine`). If omitted, zot defaults it to `["auto"]`, consistent with the Trivy CLI. See [Trivy: severity selection](https://trivy.dev/docs/latest/scanner/vulnerability/#severity-selection).

`sbom.enable` lets zot generate SBOMs while scanning and store them as OCI artifacts attached to the scanned image. `sbom.format` supports `spdx-json` (default) and `cyclonedx`.
