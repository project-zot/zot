package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/log"
)

func TestTokenCache(t *testing.T) {
	Convey("Get/Set tokens", t, func() {
		tokenCache := NewTokenCache()
		token := &bearerToken{
			Token:     "tokenA",
			ExpiresIn: 3,
			IssuedAt:  time.Now(),
		}

		token.expirationTime = token.IssuedAt.Add(time.Duration(token.ExpiresIn) * time.Second).Add(tokenBuffer)

		tokenCache.Set("repo", token)
		cachedToken := tokenCache.Get("repo")
		So(cachedToken.Token, ShouldEqual, token.Token)

		// add token which expires soon
		token2 := &bearerToken{
			Token:     "tokenB",
			ExpiresIn: 1,
			IssuedAt:  time.Now(),
		}

		token2.expirationTime = token2.IssuedAt.Add(time.Duration(token2.ExpiresIn) * time.Second).Add(tokenBuffer)

		tokenCache.Set("repo2", token2)
		cachedToken = tokenCache.Get("repo2")
		So(cachedToken.Token, ShouldEqual, token2.Token)

		time.Sleep(1 * time.Second)

		// token3 should be expired when adding a new one
		token3 := &bearerToken{
			Token:     "tokenC",
			ExpiresIn: 3,
			IssuedAt:  time.Now(),
		}

		token3.expirationTime = token3.IssuedAt.Add(time.Duration(token3.ExpiresIn) * time.Second).Add(tokenBuffer)

		tokenCache.Set("repo3", token3)
		cachedToken = tokenCache.Get("repo3")
		So(cachedToken.Token, ShouldEqual, token3.Token)

		// token2 should be expired
		token = tokenCache.Get("repo2")
		So(token, ShouldBeNil)

		time.Sleep(2 * time.Second)

		// the rest of them should also be expired
		tokenCache.Set("repo4", &bearerToken{
			Token: "tokenD",
		})

		// token1 should be expired
		token = tokenCache.Get("repo1")
		So(token, ShouldBeNil)
	})

	Convey("Error paths", t, func() {
		tokenCache := NewTokenCache()
		token := tokenCache.Get("repo")
		So(token, ShouldBeNil)

		tokenCache = nil
		token = tokenCache.Get("repo")
		So(token, ShouldBeNil)

		tokenCache = NewTokenCache()
		tokenCache.Set("repo", nil)
		token = tokenCache.Get("repo")
		So(token, ShouldBeNil)
	})
}

func TestNeedsRetryOnInsuficientScope(t *testing.T) {
	resp := http.Response{
		Status:     "401 Unauthorized",
		StatusCode: http.StatusUnauthorized,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: map[string][]string{
			"Content-Length":         {"145"},
			"Content-Type":           {"application/json"},
			"Date":                   {"Fri, 26 Aug 2022 08:03:13 GMT"},
			"X-Content-Type-Options": {"nosniff"},
		},
		Request: nil,
	}

	Convey("Test client retries on insufficient scope", t, func() {
		resp.Header["Www-Authenticate"] = []string{
			`Bearer realm="https://registry.suse.com/auth",service="SUSE Linux Docker Registry"` +
				`,scope="registry:catalog:*",error="insufficient_scope"`,
		}

		expectedScope := "registry:catalog:*"
		expectedRealm := "https://registry.suse.com/auth"
		expectedService := "SUSE Linux Docker Registry"

		needsRetry, params := needsRetryWithUpdatedScope(nil, &resp)

		So(needsRetry, ShouldBeTrue)
		So(params.scope, ShouldEqual, expectedScope)
		So(params.realm, ShouldEqual, expectedRealm)
		So(params.service, ShouldEqual, expectedService)
	})

	Convey("Test client fails on insufficient scope", t, func() {
		resp.Header["Www-Authenticate"] = []string{
			`Bearer realm="https://registry.suse.com/auth=error"`,
		}

		needsRetry, _ := needsRetryWithUpdatedScope(nil, &resp)
		So(needsRetry, ShouldBeFalse)
	})
}

func TestClient(t *testing.T) {
	Convey("Test client", t, func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client, err := New(Config{
			URL:       server.URL,
			TLSVerify: false,
		}, log.NewLogger("", ""))
		So(err, ShouldBeNil)

		Convey("Test Ping() fails", func() {
			ok := client.Ping()
			So(ok, ShouldBeFalse)
		})

		Convey("Test makeAndDoRequest() fails", func() {
			client.authType = tokenAuth
			//nolint: bodyclose
			_, _, err := client.makeAndDoRequest(http.MethodGet, "application/json", "catalog", server.URL)
			So(err, ShouldNotBeNil)
		})

		Convey("Test setupAuth() fails", func() {
			request, err := http.NewRequest(http.MethodGet, server.URL, nil) //nolint: noctx
			So(err, ShouldBeNil)

			client.authType = tokenAuth
			err = client.setupAuth(request, "catalog")
			So(err, ShouldNotBeNil)
		})
	})
}
