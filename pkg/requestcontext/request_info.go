package uac

import "context"

// request-local context key for HTTP request metadata.
var requestInfoCtxKey = Key(2) //nolint: gochecknoglobals

// GetRequestInfoCtxKey returns the context key used to store RequestInfo.
func GetRequestInfoCtxKey() *Key {
	return &requestInfoCtxKey
}

// RequestInfo holds the HTTP request metadata that should be propagated into
// event payloads for audit and observability purposes.
type RequestInfo struct {
	Addr      string
	Method    string
	UserAgent string
}

// WithRequestInfo derives a new context that carries the given RequestInfo.
func WithRequestInfo(ctx context.Context, ri RequestInfo) context.Context {
	return context.WithValue(ctx, GetRequestInfoCtxKey(), ri)
}

// RequestInfoFromContext returns the RequestInfo stored in ctx, or nil if none
// was set (e.g. when the operation was triggered internally, not via HTTP).
func RequestInfoFromContext(ctx context.Context) *RequestInfo {
	if v := ctx.Value(GetRequestInfoCtxKey()); v != nil {
		if ri, ok := v.(RequestInfo); ok {
			return &ri
		}
	}

	return nil
}
