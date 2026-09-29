package gc

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	s3aws "github.com/distribution/distribution/v3/registry/storage/driver/s3-aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/s3"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

type uploadObject struct {
	Key          string
	Size         int64
	LastModified time.Time
}

type uploadS3Endpoint struct {
	mu        sync.Mutex
	objects   map[string]uploadObject
	multipart map[string]string
	deleted   []string
	aborted   []string
}

func (endpoint *uploadS3Endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	key := strings.TrimPrefix(r.URL.Path, "/bucket/")
	query := r.URL.Query()
	w.Header().Set("Content-Type", "application/xml")
	switch {
	case r.Method == http.MethodHead:
		if object, ok := endpoint.objects[key]; ok {
			w.Header().Set("Content-Length", strconv.FormatInt(object.Size, 10))
			w.Header().Set("Last-Modified", object.LastModified.UTC().Format(http.TimeFormat))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	case r.Method == http.MethodGet && query.Has("uploads"):
		result := struct {
			XMLName     xml.Name `xml:"ListMultipartUploadsResult"`
			IsTruncated bool
			Uploads     []struct {
				Key      string
				UploadID string `xml:"UploadId"`
			} `xml:"Upload"`
		}{}
		for uploadKey, id := range endpoint.multipart {
			if strings.HasPrefix(uploadKey, query.Get("prefix")) {
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
			Contents    []uploadObject
		}{}
		keys := make([]string, 0, len(endpoint.objects))
		for objectKey := range endpoint.objects {
			keys = append(keys, objectKey)
		}
		sort.Strings(keys)
		for _, objectKey := range keys {
			if strings.HasPrefix(objectKey, query.Get("prefix")) {
				result.Contents = append(result.Contents, endpoint.objects[objectKey])
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
		_, _ = fmt.Fprint(w, "<DeleteResult/>")
	default:
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, "unexpected request: %s %s", r.Method, r.URL)
	}
}

func newUploadS3Store(t *testing.T, endpoint *uploadS3Endpoint) storageTypes.ImageStore {
	t.Helper()
	server := httptest.NewServer(endpoint)
	t.Cleanup(server.Close)
	backend, err := s3aws.FromParameters(context.Background(), map[string]any{
		"region": "us-east-1", "regionendpoint": server.URL, "bucket": "bucket",
		"accesskey": "test", "secretkey": "test", "secure": false, "forcepathstyle": true,
	})
	require.NoError(t, err)
	return imagestore.NewImageStore("/zot", "", false, false, log.NewTestLogger(),
		monitoring.NewNopMetricServer(), nil, s3.New(backend), nil, nil, nil)
}

func TestS3AbandonedUploadGC(t *testing.T) {
	for _, test := range []struct {
		name    string
		size    int64
		pending bool
	}{
		{name: "empty committed object"},
		{name: "nonempty committed object", size: 4},
		{name: "empty object with unfinished multipart upload", pending: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			old := "zot/repo/.uploads/abandoned"
			recent := "zot/repo/.uploads/active"
			endpoint := &uploadS3Endpoint{
				objects: map[string]uploadObject{
					old:    {old, test.size, time.Now().Add(-2 * time.Hour)},
					recent: {recent, test.size, time.Now()},
				},
				multipart: map[string]string{recent: "active-upload"},
			}
			if test.pending {
				endpoint.multipart[old] = "abandoned-upload"
			}
			store := newUploadS3Store(t, endpoint)
			gc := GarbageCollect{imgStore: store, log: log.NewTestLogger()}
			deleted, err := gc.deleteBlobUploads("repo", time.Hour)
			require.NoError(t, err)
			require.Equal(t, 1, deleted)
			endpoint.mu.Lock()
			assert.NotContains(t, endpoint.objects, old)
			assert.Contains(t, endpoint.objects, recent)
			assert.Equal(t, map[string]string{recent: "active-upload"}, endpoint.multipart)
			assert.Equal(t, []string{old}, endpoint.deleted)
			if test.size == 0 {
				assert.Equal(t, []string{old}, endpoint.aborted)
			} else {
				assert.Empty(t, endpoint.aborted)
			}
			endpoint.mu.Unlock()
			deleted, err = gc.deleteBlobUploads("repo", time.Hour)
			require.NoError(t, err)
			require.Zero(t, deleted)
		})
	}
}

func TestS3DeleteUncommittedUpload(t *testing.T) {
	key := "zot/repo/.uploads/pending"
	endpoint := &uploadS3Endpoint{objects: map[string]uploadObject{}, multipart: map[string]string{key: "pending-upload"}}
	store := newUploadS3Store(t, endpoint)
	require.NoError(t, store.DeleteBlobUpload("repo", "pending"))
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	require.Empty(t, endpoint.multipart)
	require.Empty(t, endpoint.deleted)
	require.Equal(t, []string{key}, endpoint.aborted)
}
