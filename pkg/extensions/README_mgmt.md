# `mgmt`

`mgmt` component provides an endpoint for configuration management

Response depends on the user privileges:
- unauthenticated and authenticated users will get a stripped config
- admins will get full configuration with passwords hidden (not implemented yet)


| Supported queries | Input | Output | Description |
| --- | --- | --- | --- |
| [Get current configuration](#get-current-configuration) | None | config json | Get current zot configuration | 
| [Run garbage collection](#run-garbage-collection) | store, optional repo | none | Start GC of a store or a repository (admin only) |
| [Get garbage collection status](#get-garbage-collection-status) | store, optional repo | status json | Get the status of the current or last GC run (admin only) |

## Get current configuration

**Sample request**

```bash
curl http://localhost:8080/v2/_zot/ext/mgmt | jq
```

**Sample response**

```json
{
  "distSpecVersion": "1.1.1",
  "binaryType": "-sync-search-scrub-metrics-lint-ui-mgmt",
  "http": {
    "auth": {
      "htpasswd": {},
      "bearer": {
        "realm": "https://auth.myreg.io/auth/token",
        "service": "myauth"
      },
      "allowAnonymousAccess": true
    }
  }
}
```

If ldap or htpasswd are enabled mgmt will return `{"htpasswd": {}}` indicating that clients can authenticate with basic auth credentials. An empty `htpasswd` object from a disabled (pathless) htpasswd config is omitted.

If `accessControl` contains any repository `anonymousPolicy`, mgmt sets `allowAnonymousAccess: true` so clients can offer guest login without probing `GET /v2/`.

If any key is present under `'auth'` key, in the mgmt response, it means that particular authentication method is enabled.

## Run garbage collection

Starts garbage collection of a store, or of a single repository in it, before the next periodic run is due.
It uses the store's own GC settings (`gcDelay`, retention policies). Only admins can use it: users or groups
in `accessControl.adminPolicy`. As elsewhere in zot, without `accessControl` every user is an admin, so any user
(or, without authentication, anyone) can request GC.

The `store` parameter is `/` for the default store, otherwise a `subPaths` key. GC must be enabled for the store.
Like the rest of `mgmt`, this endpoint is only available when the `search` extension is enabled.

- Without `repo`, the whole store is swept by the same task generator as the periodic sweep, so it is paced
  the same way: repositories are collected one after another with a random delay of up to 30 seconds between them.
  A requested sweep may start outside `gcTimeWindow`.
- With `repo`, only that repository is collected, right away. Use it when you know which repositories
  need to be collected, e.g. after deleting images from them.

**Sample request**

```bash
curl -u admin:password -X POST "http://localhost:8080/v2/_zot/ext/mgmt/gc?store=/&repo=alpine"
```

| Status | Meaning |
| --- | --- |
| 202 | GC started |
| 400 | missing `store`, or invalid `repo` name |
| 403 | not an admin |
| 404 | unknown store or repository |
| 409 | GC is disabled for the store, or GC of the store (or repository) is already running |
| 503 | GC could not be scheduled, retry later |

Once a request is accepted, the status (see below) reports the run as `running` until it has finished,
so a client can poll it to wait for the result.

A store sweep which is already running may have collected some repositories before the request,
so a request made while it runs is rejected with 409 instead of being merged into it: retry once it has finished.

## Get garbage collection status

Returns the status of the current or last requested run: of the store sweep without `repo`,
of the repository with `repo`. The store sweep status also covers periodic sweeps.
The status of a repository is kept in memory, and is not found (404) if GC was never requested for it
since zot started or its configuration was last reloaded.

**Sample request**

```bash
curl -u admin:password "http://localhost:8080/v2/_zot/ext/mgmt/gc?store=/&repo=alpine" | jq
```

**Sample response**

```json
{
  "running": false,
  "startedAt": "2026-09-28T03:12:56.543226023Z",
  "finishedAt": "2026-09-28T03:12:57.345123455Z"
}
```

`error` is set to the last error if listing or collecting repositories failed. A sweep which can't list
repositories keeps running, and is retried until it can.
