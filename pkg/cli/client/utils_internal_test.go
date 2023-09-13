//go:build search
// +build search

package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/test"
)

func getDefaultSearchConf(baseURL string) searchConfig {
	verifyTLS := false
	debug := false
	verbose := true
	outputFormat := "text"

	return searchConfig{
		servURL:      baseURL,
		resultWriter: io.Discard,
		verifyTLS:    verifyTLS,
		debug:        debug,
		verbose:      verbose,
		outputFormat: outputFormat,
	}
}

func TestDoHTTPRequest(t *testing.T) {
	Convey("doHTTPRequest nil result pointer", t, func() {
		port := test.GetFreePort()
		server := test.StartTestHTTPServer(nil, port)
		defer server.Close()

		url := fmt.Sprintf("http://127.0.0.1:%s/asd", port)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, nil)
		So(err, ShouldBeNil)

		So(func() { _, _ = doHTTPRequest(req, false, false, nil, io.Discard) }, ShouldNotPanic)
	})

	Convey("doHTTPRequest bad return json", t, func() {
		port := test.GetFreePort()
		server := test.StartTestHTTPServer(test.HTTPRoutes{
			{
				Route: "/test",
				HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					_, err := w.Write([]byte("bad json"))
					if err != nil {
						return
					}
				},
				AllowedMethods: []string{http.MethodGet},
			},
		}, port)
		defer server.Close()

		url := fmt.Sprintf("http://127.0.0.1:%s/test", port)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		So(err, ShouldBeNil)

		So(func() { _, _ = doHTTPRequest(req, false, false, &ispec.Manifest{}, io.Discard) }, ShouldNotPanic)
	})

	Convey("makeGraphQLRequest bad request context", t, func() {
		err := makeGraphQLRequest(nil, "", "", "", "", false, false, nil, io.Discard) //nolint:staticcheck
		So(err, ShouldNotBeNil)
	})

	Convey("makeHEADRequest bad request context", t, func() {
		_, err := makeHEADRequest(nil, "", "", "", false, false) //nolint:staticcheck
		So(err, ShouldNotBeNil)
	})

	Convey("makeGETRequest bad request context", t, func() {
		_, err := makeGETRequest(nil, "", "", "", false, false, nil, io.Discard) //nolint:staticcheck
		So(err, ShouldNotBeNil)
	})

	Convey("fetchImageManifestStruct errors", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		searchConf := getDefaultSearchConf(baseURL)

		// 404 erorr will appear
		server := test.StartTestHTTPServer(test.HTTPRoutes{}, port)
		defer server.Close()

		URL := baseURL + "/v2/repo/manifests/tag"

		_, err := fetchImageManifestStruct(context.Background(), &httpJob{
			url:       URL,
			username:  "",
			password:  "",
			imageName: "repo",
			tagName:   "tag",
			config:    searchConf,
		})

		So(err, ShouldNotBeNil)
	})

	Convey("fetchManifestStruct errors", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		searchConf := getDefaultSearchConf(baseURL)

		Convey("makeGETRequest manifest error, context is done", func() {
			server := test.StartTestHTTPServer(test.HTTPRoutes{}, port)
			defer server.Close()

			ctx, cancel := context.WithCancel(context.Background())

			cancel()

			_, err := fetchManifestStruct(ctx, "repo", "tag", searchConf,
				"", "")

			So(err, ShouldNotBeNil)
		})

		Convey("makeGETRequest manifest error, context is not done", func() {
			server := test.StartTestHTTPServer(test.HTTPRoutes{}, port)
			defer server.Close()

			_, err := fetchManifestStruct(context.Background(), "repo", "tag", searchConf,
				"", "")

			So(err, ShouldNotBeNil)
		})

		Convey("makeGETRequest config error, context is not done", func() {
			server := test.StartTestHTTPServer(test.HTTPRoutes{
				{
					Route: "/v2/{name}/manifests/{reference}",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						_, err := w.Write([]byte(`{"config":{"digest":"digest","size":0}}`))
						if err != nil {
							return
						}
					},
					AllowedMethods: []string{http.MethodGet},
				},
			}, port)
			defer server.Close()

			_, err := fetchManifestStruct(context.Background(), "repo", "tag", searchConf,
				"", "")

			So(err, ShouldNotBeNil)
		})

		Convey("Platforms on config", func() {
			server := test.StartTestHTTPServer(test.HTTPRoutes{
				{
					Route: "/v2/{name}/manifests/{reference}",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						_, err := w.Write([]byte(`
						{
							"config":{
								"digest":"digest",
								"size":0,
								"platform" : {
									"os": "",
									"architecture": "",
									"variant": ""
								}
							}
						}
						`))
						if err != nil {
							return
						}
					},
					AllowedMethods: []string{http.MethodGet},
				},
				{
					Route: "/v2/{name}/blobs/{digest}",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						_, err := w.Write([]byte(`
						{
							"architecture": "arch",
							"os": "os",
							"variant": "var"
						}
						`))
						if err != nil {
							return
						}
					},
					AllowedMethods: []string{http.MethodGet},
				},
			}, port)
			defer server.Close()

			_, err := fetchManifestStruct(context.Background(), "repo", "tag", searchConf,
				"", "")

			So(err, ShouldBeNil)
		})

		Convey("isNotationSigned error", func() {
			isSigned := isNotationSigned(context.Background(), "repo", "digest", searchConf,
				"", "")
			So(isSigned, ShouldBeFalse)
		})

		Convey("fetchImageIndexStruct no errors", func() {
			server := test.StartTestHTTPServer(test.HTTPRoutes{
				{
					Route: "/v2/{name}/manifests/{reference}",
					HandlerFunc: func(writer http.ResponseWriter, req *http.Request) {
						vars := mux.Vars(req)

						if vars["reference"] == "indexRef" {
							writer.Header().Add("docker-content-digest", godigest.FromString("t").String())
							_, err := writer.Write([]byte(`
								{
									"manifests": [
										{
											"digest": "manifestRef",
											"platform": {
												"architecture": "arch",
												"os": "os",
												"variant": "var"
											}
										}
									]
								}
							`))
							if err != nil {
								return
							}
						} else if vars["reference"] == "manifestRef" {
							_, err := writer.Write([]byte(`
								{
									"config":{
										"digest":"digest",
										"size":0
									}
								}
							`))
							if err != nil {
								return
							}
						}
					},
					AllowedMethods: []string{http.MethodGet},
				},
				{
					Route: "/v2/{name}/blobs/{digest}",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						_, err := w.Write([]byte(`{}`))
						if err != nil {
							return
						}
					},
					AllowedMethods: []string{http.MethodGet},
				},
			}, port)
			defer server.Close()

			URL := baseURL + "/v2/repo/manifests/indexRef"

			imageStruct, err := fetchImageIndexStruct(context.Background(), &httpJob{
				url:       URL,
				username:  "",
				password:  "",
				imageName: "repo",
				tagName:   "tag",
				config:    searchConf,
			})
			So(err, ShouldBeNil)
			So(imageStruct, ShouldNotBeNil)
		})

		Convey("fetchImageIndexStruct makeGETRequest errors context done", func() {
			server := test.StartTestHTTPServer(test.HTTPRoutes{}, port)
			defer server.Close()

			ctx, cancel := context.WithCancel(context.Background())

			cancel()

			URL := baseURL + "/v2/repo/manifests/indexRef"

			imageStruct, err := fetchImageIndexStruct(ctx, &httpJob{
				url:       URL,
				username:  "",
				password:  "",
				imageName: "repo",
				tagName:   "tag",
				config:    searchConf,
			})
			So(err, ShouldNotBeNil)
			So(imageStruct, ShouldBeNil)
		})

		Convey("fetchImageIndexStruct makeGETRequest errors context not done", func() {
			server := test.StartTestHTTPServer(test.HTTPRoutes{}, port)
			defer server.Close()

			URL := baseURL + "/v2/repo/manifests/indexRef"

			imageStruct, err := fetchImageIndexStruct(context.Background(), &httpJob{
				url:       URL,
				username:  "",
				password:  "",
				imageName: "repo",
				tagName:   "tag",
				config:    searchConf,
			})
			So(err, ShouldNotBeNil)
			So(imageStruct, ShouldBeNil)
		})
	})
}

func TestDoJobErrors(t *testing.T) {
	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)
	searchConf := getDefaultSearchConf(baseURL)

	reqPool := &requestsPool{
		jobs:     make(chan *httpJob),
		done:     make(chan struct{}),
		wtgrp:    &sync.WaitGroup{},
		outputCh: make(chan stringResult),
	}

	Convey("Do Job errors", t, func() {
		reqPool.wtgrp.Add(1)

		Convey("Do Job makeHEADRequest error context done", func() {
			server := test.StartTestHTTPServer(test.HTTPRoutes{}, port)
			defer server.Close()

			URL := baseURL + "/v2/repo/manifests/manifestRef"

			ctx, cancel := context.WithCancel(context.Background())

			cancel()

			reqPool.doJob(ctx, &httpJob{
				url:       URL,
				username:  "",
				password:  "",
				imageName: "",
				tagName:   "",
				config:    searchConf,
			})
		})

		Convey("Do Job makeHEADRequest error context not done", func() {
			server := test.StartTestHTTPServer(test.HTTPRoutes{}, port)
			defer server.Close()

			URL := baseURL + "/v2/repo/manifests/manifestRef"

			ctx := context.Background()

			go reqPool.doJob(ctx, &httpJob{
				url:       URL,
				username:  "",
				password:  "",
				imageName: "",
				tagName:   "",
				config:    searchConf,
			})

			result := <-reqPool.outputCh
			So(result.Err, ShouldNotBeNil)
			So(result.StrValue, ShouldResemble, "")
		})

		Convey("Do Job fetchManifestStruct errors context canceled", func() {
			server := test.StartTestHTTPServer(test.HTTPRoutes{
				{
					Route: "/v2/{name}/manifests/{reference}",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						w.Header().Add("Content-Type", ispec.MediaTypeImageManifest)
						_, err := w.Write([]byte(""))
						if err != nil {
							return
						}
					},
					AllowedMethods: []string{http.MethodHead},
				},
			}, port)
			defer server.Close()

			URL := baseURL + "/v2/repo/manifests/manifestRef"

			ctx, cancel := context.WithCancel(context.Background())

			cancel()
			// context not canceled

			reqPool.doJob(ctx, &httpJob{
				url:       URL,
				username:  "",
				password:  "",
				imageName: "",
				tagName:   "",
				config:    searchConf,
			})
		})

		Convey("Do Job fetchManifestStruct errors context not canceled", func() {
			server := test.StartTestHTTPServer(test.HTTPRoutes{
				{
					Route: "/v2/{name}/manifests/{reference}",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						w.Header().Add("Content-Type", ispec.MediaTypeImageManifest)
						_, err := w.Write([]byte(""))
						if err != nil {
							return
						}
					},
					AllowedMethods: []string{http.MethodHead},
				},
			}, port)
			defer server.Close()

			URL := baseURL + "/v2/repo/manifests/manifestRef"

			ctx := context.Background()

			go reqPool.doJob(ctx, &httpJob{
				url:       URL,
				username:  "",
				password:  "",
				imageName: "",
				tagName:   "",
				config:    searchConf,
			})

			result := <-reqPool.outputCh
			So(result.Err, ShouldNotBeNil)
			So(result.StrValue, ShouldResemble, "")
		})

		Convey("Do Job fetchIndexStruct errors context canceled", func() {
			server := test.StartTestHTTPServer(test.HTTPRoutes{
				{
					Route: "/v2/{name}/manifests/{reference}",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						w.Header().Add("Content-Type", ispec.MediaTypeImageIndex)
						_, err := w.Write([]byte(""))
						if err != nil {
							return
						}
					},
					AllowedMethods: []string{http.MethodHead},
				},
			}, port)
			defer server.Close()

			URL := baseURL + "/v2/repo/manifests/indexRef"

			ctx, cancel := context.WithCancel(context.Background())

			cancel()
			// context not canceled

			reqPool.doJob(ctx, &httpJob{
				url:       URL,
				username:  "",
				password:  "",
				imageName: "",
				tagName:   "",
				config:    searchConf,
			})
		})

		Convey("Do Job fetchIndexStruct errors context not canceled", func() {
			server := test.StartTestHTTPServer(test.HTTPRoutes{
				{
					Route: "/v2/{name}/manifests/{reference}",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						w.Header().Add("Content-Type", ispec.MediaTypeImageIndex)
						_, err := w.Write([]byte(""))
						if err != nil {
							return
						}
					},
					AllowedMethods: []string{http.MethodHead},
				},
			}, port)
			defer server.Close()

			URL := baseURL + "/v2/repo/manifests/indexRef"

			ctx := context.Background()

			go reqPool.doJob(ctx, &httpJob{
				url:       URL,
				username:  "",
				password:  "",
				imageName: "",
				tagName:   "",
				config:    searchConf,
			})

			result := <-reqPool.outputCh
			So(result.Err, ShouldNotBeNil)
			So(result.StrValue, ShouldResemble, "")
		})
		Convey("Do Job fetchIndexStruct not supported content type", func() {
			server := test.StartTestHTTPServer(test.HTTPRoutes{
				{
					Route: "/v2/{name}/manifests/{reference}",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						w.Header().Add("Content-Type", "some-media-type")
						_, err := w.Write([]byte(""))
						if err != nil {
							return
						}
					},
					AllowedMethods: []string{http.MethodHead},
				},
			}, port)
			defer server.Close()

			URL := baseURL + "/v2/repo/manifests/indexRef"

			ctx := context.Background()

			reqPool.doJob(ctx, &httpJob{
				url:       URL,
				username:  "",
				password:  "",
				imageName: "",
				tagName:   "",
				config:    searchConf,
			})
		})

		Convey("Media type is MediaTypeImageIndex image.string erorrs", func() {
			server := test.StartTestHTTPServer(test.HTTPRoutes{
				{
					Route: "/v2/{name}/manifests/{reference}",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						w.Header().Add("Content-Type", ispec.MediaTypeImageIndex)
						w.Header().Add("docker-content-digest", godigest.FromString("t").String())

						_, err := w.Write([]byte(""))
						if err != nil {
							return
						}
					},
					AllowedMethods: []string{http.MethodHead},
				},
				{
					Route: "/v2/{name}/manifests/{reference}",
					HandlerFunc: func(writer http.ResponseWriter, req *http.Request) {
						vars := mux.Vars(req)

						if vars["reference"] == "indexRef" {
							writer.Header().Add("docker-content-digest", godigest.FromString("t").String())

							_, err := writer.Write([]byte(`{"manifests": [{"digest": "manifestRef"}]}`))
							if err != nil {
								return
							}
						}

						if vars["reference"] == "manifestRef" {
							writer.Header().Add("docker-content-digest", godigest.FromString("t").String())

							_, err := writer.Write([]byte(`{"config": {"digest": "confDigest"}}`))
							if err != nil {
								return
							}
						}
					},
					AllowedMethods: []string{http.MethodGet},
				},
				{
					Route: "/v2/{name}/blobs/{digest}",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						_, err := w.Write([]byte(`{}`))
						if err != nil {
							return
						}
					},
					AllowedMethods: []string{http.MethodGet},
				},
			}, port)
			defer server.Close()
			URL := baseURL + "/v2/repo/manifests/indexRef"

			go reqPool.doJob(context.Background(), &httpJob{
				url:       URL,
				username:  "",
				password:  "",
				imageName: "repo",
				tagName:   "indexRef",
				config:    searchConf,
			})

			result := <-reqPool.outputCh
			So(result.Err, ShouldNotBeNil)
			So(result.StrValue, ShouldResemble, "")
		})
	})
}
