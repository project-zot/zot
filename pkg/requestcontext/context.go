package requestcontext

type Key int

// request-local context key.
var authzCtxKey = Key(0) // nolint: gochecknoglobals

// pointer needed for use in context.WithValue.
func GetContextKey() *Key {
	return &authzCtxKey
}

// AccessControlContext context passed down to http.Handlers.
type AccessControlContext struct {
	GlobPatterns map[string]bool
	IsAdmin      bool
	Username     string
}
