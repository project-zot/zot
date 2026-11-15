# Browser authentication and logout

> **Serve zot over HTTPS if the UI is used with more than one account.**
> On plain HTTP, logging out cannot clear Basic authentication credentials
> cached by the browser, so the previous account can keep coming back.
> TLS terminated at a reverse proxy is sufficient.

## How it works

The zot UI uses a session cookie after signing in with `htpasswd` or LDAP.
Registry clients such as Docker continue to use HTTP Basic authentication.

HTTP Basic authentication has no logout. When a browser answers a
`WWW-Authenticate: Basic` challenge through its native login prompt, it caches
those credentials per origin and realm and keeps re-sending them. zot checks a
Basic `Authorization` header before the session cookie, so cached credentials
override a later UI login as a different user.

To prevent that:

- zot omits the Basic challenge for browser requests: UI requests, requests
  carrying Fetch Metadata (`Sec-Fetch-Mode`), and requests accepting
  `text/html`, including direct navigation to `/v2/` URLs. Authentication is
  still required; only the challenge header (and so the native prompt) is
  omitted. Signing in through the browser's native prompt is therefore no
  longer offered; use the UI login form.
  This covers authentication and authorization failures alike (e.g. an
  anonymous visit to `/v2/_catalog` with `disableAnonymousCatalog`, or to an
  admin route), as well as Basic challenges returned by an upstream token
  endpoint (`bearer.upstreamTokenEndpoint`) that zot proxies. Bearer challenges
  are unaffected.
- A successful `POST /zot/auth/logout` expires the session cookie and sends
  `Clear-Site-Data: "cookies"`, which in supporting browsers also clears cached
  HTTP Basic credentials, so the next UI login can use a different account.
  The header is only sent for logout requests from the zot origin itself
  (`Sec-Fetch-Site: same-origin`) or from an origin listed in
  `http.allowOrigin` or `http.externalUrl` (scheme, host and port must match;
  `*` does not count), so other
  sites cannot use a cross-site form POST to wipe your cookies. If the UI is
  served from a different origin than zot, list that origin explicitly.

`Clear-Site-Data: "cookies"` clears cookies for the entire registrable domain,
including subdomains, so logging out of zot may also sign you out of other
applications sharing that domain. It does not clear local storage or the
browser's resource cache.

## Limitations

Browsers honor `Clear-Site-Data` only in secure contexts (HTTPS or
`localhost`), and not every browser clears HTTP authentication credentials for
it. In those cases logout cannot remove credentials that were already cached by
a native Basic prompt.

On plain HTTP, browsers also omit Fetch Metadata, so zot can only recognize
page navigations (which accept `text/html`) and UI requests carrying the zot
UI header. A script request issued without that header is indistinguishable
from a registry client and may still receive a Basic challenge.

## Clearing cached credentials manually

If the previous account keeps reappearing after logout:

1. Fully quit the browser. Basic credentials are usually held only in memory.
   In Chrome/Edge, also make sure no background process keeps running
   (*Settings → System → Continue running background apps*).
2. Or clear the site's data: in Chrome/Edge use the site-info icon in the
   address bar → *Site settings* → *Delete data*; in Firefox use
   *History → Clear recent history* → *Cookies and site data*
   (and *Active logins*, where offered).
3. Remove any zot entry saved by the browser's password manager, otherwise the
   native prompt is auto-filled again.
4. A private/incognito window starts with an empty credential cache and is a
   quick way to sign in as a different user.
