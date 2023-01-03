# `API keys`

zot allows authentication for REST API calls using your API key as an alternative to your password.

* User can create/revoke his API key.

* Can not be retrieved, it is shown to the user only the first time is created.

* An API key has the same rights as the user who generated it.

## API keys REST API


### Create API Key
**Description**: Create an API key for the current user.

**Usage**: POST /v2/_zot/ext/apikey

**Produces**: application/json

**Sample input**:
```
POST /api/security/apiKey
Body: {"label": "git", "scopes": ["repo1", "repo2"]}'
```

**Example cURL**
```
curl -u user:password -X POST http://localhost:8080/v2/_zot/ext/apikey -d '{"label": "myLabel", "scopes": ["repo1", "repo2"]}'
```

**Sample output**:
```json
{
  "createdAt": "2023-05-05T15:39:28.420926+03:00",
  "creatorUa": "curl/7.68.0",
  "generatedBy": "manual",
  "lastUsed": "2023-05-05T15:39:28.4209282+03:00",
  "label": "git",
  "scopes": [
    "repo1",
    "repo2"
  ],
  "uuid": "46a45ce7-5d92-498a-a9cb-9654b1da3da1",
  "apiKey": "zak_e77bcb9e9f634f1581756abbf9ecd269"
}
```

**Using API keys cURL**
```
curl -u user:zak_e77bcb9e9f634f1581756abbf9ecd269 http://localhost:8080/v2/_catalog
```


### Revoke API Key
**Description**: Revokes one current user API key by api key UUID

**Usage**: DELETE /api/security/apiKey?id=$uuid

**Produces**: application/json


**Example cURL**
```
curl -u user:password -X DELETE http://localhost:8080/v2/_zot/ext/apikey?id=46a45ce7-5d92-498a-a9cb-9654b1da3da1
```
