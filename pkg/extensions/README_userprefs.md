# `userprefs`

`userprefs` component provides endpoints for adding user preferences for repos and reading the authenticated user's profile data.
It is available only to authenticated users. Unauthenticated users will be denied access.

| Supported endpoints | Input | Output | Description |
| --- | --- | --- | --- |
| [Toggle repo star](#toggle-repo-star) | None | None | Sets the repo starred property to true if it is false, and to false if it is true |
| [Toggle repo bookmark](#toggle-repo-bookmark) | None | None | Sets the repo bookmarked property to true if it is false, and to false if it is true |
| [Get user profile](#get-user-profile) | None | JSON | Returns the authenticated user's username and groups |

## General usage
The userprefs endpoint accepts as a query parameter what `action` to perform and then all other required parameters for the specified action.

## Toggle repo star
| Action | Parameter | Parameter Type | Parameter Description |
| --- | --- | --- | --- |
| toggleStar | repo | string | The repo name which should be starred |

A request to toggle a star on a repo would look like this:
```
(PUT) http://localhost:8080/v2/_zot/ext/userprefs?action=toggleStar&repo=repoName
```

## Toggle repo bookmark
| Action | Parameter | Parameter Type | Parameter Description |
| --- | --- | --- | --- |
| toggleBookmark | repo | string | The repo name which should be bookmarked |

A request to toggle a bookmark on a repo would look like this:
```
(PUT) http://localhost:8080/v2/_zot/ext/userprefs?action=toggleBookmark&repo=repoName
```

## Get user profile
The profile endpoint returns the username and groups currently associated with the authenticated request.
This is useful for checking authorization data from OIDC, LDAP, mTLS, or local group configuration.

```
(GET) http://localhost:8080/v2/_zot/ext/userprefs/profile
```

Example response:
```
{
  "username": "alice",
  "groups": ["developers", "release-admins"]
}
```
