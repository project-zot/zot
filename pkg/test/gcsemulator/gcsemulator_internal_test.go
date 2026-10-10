//nolint:testpackage // needs unexported bucketAlreadyExists
package gcsemulator

import (
	"net/http"
	"testing"

	"google.golang.org/api/googleapi"
)

// stubError is a plain error string used to exercise already-exists matching
// without defining dynamic errors.New values (err113).
type stubError string

func (e stubError) Error() string { return string(e) }

func TestBucketAlreadyExists(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "conflict", err: &googleapi.Error{Code: http.StatusConflict}, want: true},
		{name: "not found", err: &googleapi.Error{Code: http.StatusNotFound}, want: false},
		{name: "plain 409", err: stubError("http 409 conflict"), want: true},
		{name: "AlreadyExists", err: stubError("rpc AlreadyExists"), want: true},
		{name: "already exists", err: stubError("bucket already exists"), want: true},
		{name: "owned", err: stubError("bucketAlreadyOwnedByYou"), want: true},
		{name: "other", err: stubError("permission denied"), want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := bucketAlreadyExists(tc.err); got != tc.want {
				t.Fatalf("bucketAlreadyExists(%v)=%v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
