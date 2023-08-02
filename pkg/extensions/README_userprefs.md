# `userprefs`

`userprefs` component provides an endpoint for adding user preferences for repos. It is available only to authentificated users. Unauthentificated users will be denied access.

| Supported queries | Input | Output | Description |
| --- | --- | --- | --- |
| [Toggle repo star](#toggle-repo-star) | None | None | Sets the repo starred property to true if it is false, and to false if it is true | 
| [Toggle repo bookmark](#toggle-repo-bookmark) | None | None | Sets the repo bookmarked property to true if it is false, and to false if it is true | 

## General usage
The userprefs endpoint accepts as a query parameter what `action` to perform and then all other required parameters for the specified action.

## Toggle repo star
| Action | Parameter | Parameter Type | Parameter Description |
| --- | --- | --- | --- |
| toggleStar | repo | string | The repo name which should be starred |

A request to togle a star on a repo would look like this:
```
(PUT) http://localhost:8080/v2/_zot/ext/userprefs?action=toggleStar&repo=repoName
```

## Toggle repo bookmark
| Action | Parameter | Parameter Type | Parameter Description |
| --- | --- | --- | --- |
| toggleBookmark | repo | string | The repo name which should be bookmarked |

A request to togle a bookmark on a repo would look like this:
```
(PUT) http://localhost:8080/v2/_zot/ext/userprefs?action=toggleBookmark&repo=repoName
```
