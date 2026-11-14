# Browser authentication and logout

The zot UI uses a session cookie after signing in with `htpasswd` or LDAP.
Registry clients such as Docker continue to use HTTP Basic authentication.
To avoid the browser's native login prompt and independent credential cache,
zot suppresses Basic authentication challenges for UI requests, requests with
browser Fetch Metadata (`Sec-Fetch-Mode`), and requests accepting `text/html`,
including direct navigation to `/v2/` URLs. Authentication is still required;
only the challenge header is omitted.

Successful `POST /zot/auth/logout` responses expire the session cookie and send
`Clear-Site-Data: "cookies"`. In supporting browsers this also clears cached HTTP
Basic credentials, allowing the next UI login to use a different account.
The directive clears cookies for the entire registered domain, including
subdomains, so it may sign you out of other applications sharing that domain.
It does not clear local storage or the browser's resource cache.

Browsers honor `Clear-Site-Data` only in secure contexts (normally HTTPS).
Use HTTPS, including when TLS terminates at a reverse proxy. On insecure HTTP
or browsers without support for clearing HTTP authentication credentials,
session logout alone cannot remove credentials previously saved by a native
Basic authentication prompt. If the previous account keeps reappearing, clear
the browser's site data/authentication state or close all browser windows
before signing in again; a fresh private browsing session is another workaround.
Prefer the UI login form rather than the browser's native Basic login prompt.