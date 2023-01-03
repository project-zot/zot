# API keys

Zot allows authentication for REST API calls using your API key as an alternative to your password.

* User can create/revoke/regenerate his API key.

* Each user has only one API key at a time.

* Can not be retrieve, it is shown to the user only the first time is created/regenerated.

* An API key has the same rights as the user who generated it.

* Admin can revoke a user API key.

* Admin can revoke all API keys.


## API keys REST API


### Create API Key
**Description**: Create an API key for the current user. Returns an error if API key already exists - use regenerate API key instead.

**Usage**: POST /api/security/apiKey

**Produces**: application/json

**Sample input**:
```
POST /api/security/apiKey
```

**Sample output**:
```
{
    "apiKey": "3OloposOtVFyCMrT+cXmCAScmVMPrSYXkWIjiyDCXsY="
}
```

### Regenerate API Key
**Description**: Regenerate an API key for the current user

**Usage**: PUT /api/security/apiKey

**Produces**: application/json

**Sample input**:
```
PUT /api/security/apiKey
```

**Sample output**:

```
{
    "apiKey": "3OloposOtVFyCMrT+cXmCAScmVMPrSYXkWIjiyDCXsY="
}
```

### Revoke API Key
**Description**: Revokes the current user's API key

**Usage**: DELETE /api/security/apiKey

**Produces**: application/json

### Revoke User API Key
**Description**: Revokes the API key of another user

**Security**: Requires a privileged user (Admin only)

**Usage**: DELETE /api/security/apiKey/{username} 

**Produces**: application/json

### Revoke All API Keys
**Description**: Revokes all API keys currently defined in the system

**Security**: Requires a privileged user (Admin only)

**Usage**: DELETE /api/security/apiKey?deleteAll={0/1}

**Produces**: application/json
