# Per-user repository namespaces

`config-user-namespaces.json` grants authenticated users pull and push access to
repositories beneath their own username. For example, `laurivosandi` can push and
pull `zot.registry.ee-lte-1.codemowers.io/laurivosandi/app:latest`, including nested
repositories such as `laurivosandi/team/app`. Other users and anonymous callers
cannot access that namespace with this configuration. Deletion is not granted;
add `delete` to the actions if needed.

Repository ACL patterns support `${username}`, substituted with the authenticated
username before glob matching. Use `defaultPolicy` to grant the listed actions to
the authenticated owner of the resolved namespace. Existing user, group, and
condition checks still apply when used instead. Configure your authentication
provider to return the intended username; the example uses htpasswd, and the
same ACL works with authentication flows using configuration-based authorization.
Traditional registry bearer-token authorization still uses token access claims.

Substitution is case-sensitive and requires a username that is a single valid
repository-name component (lowercase letters, digits, and valid separators).
Anonymous users and usernames containing slashes, glob syntax, or other invalid
characters do not match templated rules. Usernames are never normalized.

The longest matching resolved pattern wins, just as with ordinary ACL patterns.
A static rule overrides a template resolving to exactly the same pattern, so an
explicit `reserved/**` rule can reserve that namespace. Admin grants and other
configured repository rules continue to apply; avoid broader grants if namespaces
must remain private. Catalog filtering uses the same resolved patterns.
