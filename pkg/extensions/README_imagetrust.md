# Image Trust

The `imagetrust` extension provides a mechanism to verify image signatures using certificates and public keys

## How to configure zot for verifying signatures

In order to configure zot for verifying signatures, the user should first enable this feature:

```json
    "extensions": {
        "trust": {
            "enable": true,
            "cosign": true,
            "notation": true
        }
    }
```

In order for verification to run, the user needs to enable at least one of the cosign or notation options above.

## Uploading public keys or certificates

Next the user needs to upload the keys or certificates used for the verification.

| Supported queries | Input | Output | Description |
| --- | --- | --- | --- |
| Upload a certificate | certificate | None | Add certificate for verifying notation signatures|
| Upload a public key | public key | None | Add public key for verifying cosign signatures |

### Uploading a Cosign public key

The Cosign public keys uploaded correspond to the private keys used to sign images with `cosign`.

***Example of request***

```bash
curl --data-binary @file.pub -X POST "http://localhost:8080/v2/_zot/ext/cosign
```

As a result of this request, the uploaded file will be stored in `_cosign` directory
under the rootDir specified in the zot config or in Secrets Manager.

### Uploading a Notation certificate

Notation certificates are used to sign images with the `notation` tool.
The user needs to specify the type of the truststore through the `truststoreType`
query parameter.
`truststoreType` defaults to `ca`.

***Example of request***

```bash
curl --data-binary @certificate.crt -X POST "http://localhost:8080/v2/_zot/ext/notation?truststoreType=ca"
```

As a result of this request, the uploaded file will be stored in `_notation/truststore/x509/{truststoreType}/default`
directory under the rootDir specified in the zot config or in Secrets Manager.

## Verification and results

Based on the uploaded files, signatures verification will be performed for all the signed images.
The information determined about the signatures will be:

- the tool used to generate the signature (`cosign` or `notation`)
- info about the trustworthiness of the signature (if there is a certificate or a public key which can successfully verify the signature)
- the author of the signature which will be:

  - the public key -> for signatures generated using `cosign`
  - the subject of the certificate -> for signatures generated using `notation`

The information above will be included in the ManifestSummary objects returned by the `search` extension.

***Example of GraphQL output***

```json
{
    "data": {
        "Image": {
            "Manifests": [
                {
                    "Digest":"sha256:6c19fba547b87bde9a45df2f8563e0c61826d098dd30192a2c8b86da1e1a6360"
                }
            ],
            "IsSigned": true,
            "Tag": "latest",
            "SignatureInfo":[
                {
                    "Tool":"cosign",
                    "IsTrusted":false,
                    "Author":""
                },
                {
                    "Tool":"cosign",
                    "IsTrusted":false,
                    "Author":""
                },
                {
                    "Tool":"cosign",
                    "IsTrusted": true,
                    "Author":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9pN+/hGcFlh4YYaNvZxNvuh8Qyhl\npURz77qScOHe3DqdmiWiuqIseyhEdjEDwpL6fHRwu3a2Nd9wbKqm0la76w==\n-----END PUBLIC KEY-----\n"
                },
                {
                    "Tool":"notation",
                    "IsTrusted": false,
                    "Author":"CN=v4-test,O=Notary,L=Seattle,ST=WA,C=US"
                },
                {
                    "Tool":"notation",
                    "IsTrusted": true,
                    "Author":"CN=multipleSig,O=Notary,L=Seattle,ST=WA,C=US"
                }
            ]
        }
    }
}
```

## Notes

- The files (public keys and certificates) uploaded using the exposed routes will be stored in some specific directories called `_cosign` and `_notation` under `$rootDir` in case of local filesystem or in Secrets Manager in case of cloud.

   - `_cosign` directory will contain the uploaded public keys

        ```
        _cosign
        ├── $publicKey1
        └── $publicKey2
        ```

   - `_notation` directory will have this structure:

        ```
        _notation
        ├── trustpolicy.json
        └── truststore
            └── x509
                └── $truststoreType
                    └── default
                        └── $certificate
        ```

        where `trustpolicy.json` file has this default content which can not be modified by the user:

        ```json
        {
            "version": "1.0",
            "trustPolicies": [
                {
                    "name": "default-config",
                    "registryScopes": [ "*" ],
                    "signatureVerification": {
                        "level" : "strict" 
                    },
                    "trustStores": ["ca:default","signingAuthority:default"],
                    "trustedIdentities": [
                        "*"
                    ]
                }
            ]
        }
        ```
