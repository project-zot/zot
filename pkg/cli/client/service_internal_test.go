//go:build search

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestGetImageSkipsOnlyWellFormedCosignSignatures(t *testing.T) {
	Convey("getImage hides legacy cosign signature tags but lists malformed lookalikes", t, func() {
		validSig := "sha256-" + strings.Repeat("a", 64) + ".sig"
		tags := []string{"1.0", validSig, "sha256-abc.sig", "sha256-imagesig"}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v2/repo/tags/list" {
				http.NotFound(w, r)

				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "repo", "tags": tags})
		}))
		defer server.Close()

		config := SearchConfig{ServURL: server.URL}
		rch := make(chan stringResult, len(tags))

		// The pool is never started, so submitted manifest jobs stay queued for inspection.
		var poolWg sync.WaitGroup
		pool := newSmoothRateLimiter(&poolWg, rch)

		var wtgrp sync.WaitGroup

		wtgrp.Add(1)
		NewSearchService().(*searchService).getImage(context.Background(), config, "", "", "repo",
			rch, &wtgrp, pool)

		wantTags := []string{"1.0", "sha256-abc.sig", "sha256-imagesig"}

		gotTags := []string{}

		for range wantTags {
			select {
			case job := <-pool.jobs:
				gotTags = append(gotTags, job.tagName)
			case res := <-rch:
				So(res.Err, ShouldBeNil)
			case <-time.After(5 * time.Second):
				So("timed out waiting for manifest jobs", ShouldBeEmpty)
			}
		}

		sort.Strings(gotTags)
		So(gotTags, ShouldResemble, wantTags)

		// The well-formed signature tag must not have been queued.
		select {
		case job := <-pool.jobs:
			So(job.tagName, ShouldBeEmpty)
		case <-time.After(200 * time.Millisecond):
		}
	})
}
