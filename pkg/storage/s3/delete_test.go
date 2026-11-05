package s3_test

import (
	"context"
	"encoding/xml"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	s3aws "github.com/distribution/distribution/v3/registry/storage/driver/s3-aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage/s3"
)

type deleteS3Endpoint struct {
	mu              sync.Mutex
	objects         map[string]int64
	multipart       map[string]string
	deniedMultipart string
	deleted         []string
	aborted         []string
	requests        []string
}

func (endpoint *deleteS3Endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()

	key := strings.TrimPrefix(r.URL.Path, "/bucket/")
	query := r.URL.Query()
	endpoint.requests = append(endpoint.requests, requestKind(r.Method, query))
	w.Header().Set("Content-Type", "application/xml")

	switch {
	case r.Method == http.MethodHead:
		if size, ok := endpoint.objects[key]; ok {
			w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
			w.Header().Set("Last-Modified", time.Unix(0, 0).UTC().Format(http.TimeFormat))

			return
		}

		w.WriteHeader(http.StatusNotFound)
	case r.Method == http.MethodGet && query.Has("uploads"):
		prefix := query.Get("prefix")
		if endpoint.deniedMultipart != "" && strings.HasPrefix(prefix, endpoint.deniedMultipart) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, "<Error><Code>AccessDenied</Code><Message>denied</Message></Error>")

			return
		}

		result := struct {
			XMLName     xml.Name `xml:"ListMultipartUploadsResult"`
			IsTruncated bool
			Uploads     []struct {
				Key      string
				UploadID string `xml:"UploadId"`
			} `xml:"Upload"`
		}{}

		for uploadKey, id := range endpoint.multipart {
			if strings.HasPrefix(uploadKey, prefix) {
				result.Uploads = append(result.Uploads, struct {
					Key      string
					UploadID string `xml:"UploadId"`
				}{uploadKey, id})
			}
		}

		_ = xml.NewEncoder(w).Encode(result)
	case r.Method == http.MethodGet && query.Has("uploadId"):
		_, _ = fmt.Fprint(w, "<ListPartsResult><IsTruncated>false</IsTruncated></ListPartsResult>")
	case r.Method == http.MethodGet && query.Get("list-type") == "2":
		result := struct {
			XMLName     xml.Name `xml:"ListBucketResult"`
			IsTruncated bool
			Contents    []struct {
				Key  string
				Size int64
			}
		}{}

		keys := make([]string, 0, len(endpoint.objects))
		for objectKey := range endpoint.objects {
			keys = append(keys, objectKey)
		}

		sort.Strings(keys)

		for _, objectKey := range keys {
			if strings.HasPrefix(objectKey, query.Get("prefix")) {
				result.Contents = append(result.Contents, struct {
					Key  string
					Size int64
				}{objectKey, endpoint.objects[objectKey]})

				if query.Get("max-keys") == "1" {
					break
				}
			}
		}

		_ = xml.NewEncoder(w).Encode(result)
	case r.Method == http.MethodPost && query.Has("uploads"):
		endpoint.multipart[key] = "new-upload"
		_, _ = fmt.Fprint(w, "<InitiateMultipartUploadResult><UploadId>new-upload</UploadId></InitiateMultipartUploadResult>")
	case r.Method == http.MethodDelete && query.Has("uploadId"):
		delete(endpoint.multipart, key)
		endpoint.aborted = append(endpoint.aborted, key)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && query.Has("delete"):
		var request struct {
			Objects []struct{ Key string } `xml:"Object"`
		}

		if err := xml.NewDecoder(r.Body).Decode(&request); err != nil {
			panic(err)
		}

		for _, object := range request.Objects {
			delete(endpoint.objects, object.Key)
			endpoint.deleted = append(endpoint.deleted, object.Key)
		}

		sort.Strings(endpoint.deleted)
		_, _ = fmt.Fprint(w, "<DeleteResult/>")
	default:
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, "<Error><Code>InvalidRequest</Code></Error>")
	}
}

func requestKind(method string, query url.Values) string {
	for _, op := range []string{"uploads", "uploadId", "delete"} {
		if query.Has(op) {
			return method + " ?" + op
		}
	}

	if query.Get("list-type") == "2" {
		return method + " ?list-type=2"
	}

	return method
}

func newDeleteS3Driver(t *testing.T, endpoint *deleteS3Endpoint) *s3.Driver {
	t.Helper()

	server := httptest.NewServer(endpoint)
	t.Cleanup(server.Close)

	backend, err := s3aws.FromParameters(context.Background(), map[string]any{
		"region": "us-east-1", "regionendpoint": server.URL, "bucket": "bucket",
		"accesskey": "test", "secretkey": "test", "secure": false, "forcepathstyle": true,
	})
	require.NoError(t, err)

	return s3.New(backend)
}

func TestDriverDeleteUploadKey(t *testing.T) {
	const (
		objectOnly    = "repo/.uploads/object-only"
		emptyObject   = "repo/.uploads/empty-object"
		multipartOnly = "repo/.uploads/multipart-only"
		both          = "repo/.uploads/object-and-multipart"
		denied        = "repo/.uploads/denied"
		blob          = "repo/blobs/sha256/0123"
	)

	objects := map[string]int64{objectOnly: 4, emptyObject: 0, both: 4, denied: 4, blob: 4}
	multipart := map[string]string{multipartOnly: "m", both: "b", denied: "d", blob: "pending-blob"}

	for _, test := range []struct {
		name         string
		key          string
		wantErr      error
		wantDeleted  []string
		wantAborted  []string
		wantRequests []string
	}{
		{name: "object only", key: objectOnly, wantDeleted: []string{objectOnly}},
		{name: "empty object", key: emptyObject, wantDeleted: []string{emptyObject}, wantAborted: []string{emptyObject}},
		{name: "multipart only", key: multipartOnly, wantAborted: []string{multipartOnly}},
		{name: "object and multipart", key: both, wantDeleted: []string{both}, wantAborted: []string{both}},
		{name: "multipart list denied", key: denied, wantErr: zerr.ErrStoragePermanent},
		{name: "missing upload", key: "repo/.uploads/missing", wantErr: zerr.ErrStorageMissing},
		{
			name: "uploads directory", key: "repo/.uploads",
			wantDeleted: []string{denied, emptyObject, both, objectOnly},
		},
		{
			name: "blob", key: blob, wantDeleted: []string{blob},
			wantRequests: []string{"GET ?list-type=2", "POST ?delete"},
		},
		{
			name: "missing blob", key: "repo/blobs/sha256/4567", wantErr: zerr.ErrStorageMissing,
			wantRequests: []string{"GET ?list-type=2"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoint := &deleteS3Endpoint{
				objects:         maps.Clone(objects),
				multipart:       maps.Clone(multipart),
				deniedMultipart: denied,
			}
			driver := newDeleteS3Driver(t, endpoint)

			err := driver.Delete("/" + test.key)
			require.ErrorIs(t, err, test.wantErr)

			endpoint.mu.Lock()
			defer endpoint.mu.Unlock()

			assert.Equal(t, test.wantDeleted, endpoint.deleted)
			assert.Equal(t, test.wantAborted, endpoint.aborted)
			assert.ElementsMatch(t, remaining(objects, test.wantDeleted), keysOf(endpoint.objects))
			assert.ElementsMatch(t, remaining(multipart, test.wantAborted), keysOf(endpoint.multipart))

			if test.wantRequests != nil {
				assert.Equal(t, test.wantRequests, endpoint.requests)
			}
		})
	}
}

func remaining[V any](values map[string]V, removed []string) []string {
	keys := []string{}

	for key := range values {
		if !slices.Contains(removed, key) {
			keys = append(keys, key)
		}
	}

	return keys
}

func keysOf[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	return keys
}
