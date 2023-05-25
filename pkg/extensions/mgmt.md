# `mgmt`

`mgmt` component provides an endpoint for configuration management

Response depends on the user privileges:
- unauthenticated and authenticated users will get a stripped config
- admins will get full configuration with passwords hidden (not implemented yet)


| Supported queries | Input | Output | Description |
| --- | --- | --- | --- |
| [Get current configuration](#get-current-configuration) | None | config json | Get current zot configuration | 
| [Upload a certificate](#post-certificate) | certificate | None | Add certificate for verifying notation signatures| 
| [Upload a public key](#post-public-key) | public key | None | Add public key for verifying cosign signatures | 

## General usage
The mgmt endpoint accepts as a query parameter what `resource` is targeted by the request and then all other required parameters for the specified resource. The default value of this
query parameter is `config`.

## Get current configuration

**Sample request**

```bash
curl http://localhost:8080/v2/_zot/ext/mgmt | jq
```

**Sample response**

```json
{
  "distSpecVersion": "1.1.0-dev",
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

## Configure zot for verifying signatures
If the `resource` is `signatures` then the mgmt endpoint accepts as a query parameter the `tool` that corresponds to the uploaded file and then all other required parameters for the specified tool.

### Upload a certificate

**Sample request**

| Tool | Parameter | Parameter Type | Parameter Description |
| --- | --- | --- | --- |
| notation | truststoreType | string | The type of the truststore. This parameter is optional and its default value is `ca` |
|  | truststoreName | string | The name of the truststore |

```bash
curl --data-binary @certificate.crt -X POST http://localhost:8080/v2/_zot/ext/mgmt?resource=signature&tool=notation&truststoreType=ca&truststoreName=newtruststore
```
As a result of this request, the uploaded file will be stored in `_notation/truststore/x509/{truststoreType}/{truststoreName}` directory under $rootDir. And `truststores` field from `_notation/trustpolicy.json` file will be updated.

### Upload a public key

**Sample request**

| Tool | Parameter | Parameter Type | Parameter Description |
| --- | --- | --- | --- |
| cosign |


```bash
curl --data-binary @publicKey.pub -X POST http://localhost:8080/v2/_zot/ext/mgmt?resource=signature&tool=cosign
```

As a result of this request, the uploaded file will be stored in `_cosign` directory under $rootDir.
