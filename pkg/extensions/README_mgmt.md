# `mgmt`

`mgmt` component provides an endpoint for configuration management

Response depends on the user privileges:
- unauthenticated and authenticated users will get a stripped config
- admins will get full configuration with passwords hidden (not implemented yet)


| Supported queries | Input | Output | Description |
| --- | --- | --- | --- |
| [Get current configuration](#get-current-configuration) | None | config json | Get current zot configuration | 

## Get current configuration

**Sample request**

```bash
curl http://localhost:8080/v2/_zot/ext/mgmt | jq
```

**Sample response**

```json
{
  "distSpecVersion": "1.1.0",
  "binaryType": "-sync-search-scrub-metrics-lint-ui-mgmt",
  "http": {
    "auth": {
      "htpasswd": {},
      "bearer": {
        "realm": "https://auth.myreg.io/auth/token",
        "service": "myauth"
      }
    }
  }
}
```

If ldap or htpasswd are enabled mgmt will return `{"htpasswd": {}}` indicating that clients can authenticate with basic auth credentials.

If any key is present under `'auth'` key, in the mgmt response, it means that particular authentication method is enabled.
