# Verifying signatures

## How to configure zot for verifying signatures

In order to configure zot for verifying signatures, the user should provide:

1. public keys (which correspond to the private keys used to sign images with `cosign`)

or 

2. certificates (used to sign images with `notation`)

These files could be uploaded using one of these requests:

1. upload a public key

    ***Example of request***
    ```
    curl --data-binary @file.pub -X POST "http://localhost:8080/v2/_zot/ext/mgmt?resource=signatures&tool=cosign"
    ```

2. upload a certificate

    ***Example of request***
    ```
    curl --data-binary @filet.crt -X POST "http://localhost:8080/v2/_zot/ext/mgmt?resource=signatures&tool=notation&truststoreType=ca&truststoreName=upload-cert"
    ```

Besides the requested files, the user should also specify the `tool` which should be :
    
- `cosign` for uploading public keys
- `notation` for uploading certificates

 Also, if the uploaded file is a certificate then the user should also specify the type of the truststore through `truststoreType` param and also its name through `truststoreName` param.

 Based on the uploaded files, signatures verification will be performed for all the signed images. Then the information known about the signatures will be:
    
- the tool used to generate the signature (`cosign` or `notation`)
- info about the trustworthiness of the signature (if there is a certificate or a public key which can successfully verify the signature)
- the author of the signature which will be:
    
    - the public key -> for signatures generated using `cosign`
    - the subject of the certificate -> for signatures generated using `notation`

**Example of GraphQL output**

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

- The files (public keys and certificates) uploaded using the exposed routes will be stored in some specific directories called `_cosign` and `_notation` under `$rootDir`.
   
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
	                └── $truststoreName
	                    └── $certificate
        ```

        where `trustpolicy.json` file has this default content which can not be modified by the user and which is updated each time a new certificate is added to a new truststore:
        ```
        {
            "version": "1.0",
            "trustPolicies": [
                {
                    "name": "default-config",
                    "registryScopes": [ "*" ],
                    "signatureVerification": {
                        "level" : "strict" 
                    },
                    "trustStores": [],
                    "trustedIdentities": [
                        "*"
                    ]
                }
            ]
	    }
        ```

