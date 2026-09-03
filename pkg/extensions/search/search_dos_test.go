//go:build search

package search_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	. "zotregistry.dev/zot/v2/pkg/test/common"
)

// buildRepeatedFieldQuery builds a single valid GraphQL document containing count repeated,
// unaliased selections of the same root field - the shape that forces validation's field-merge
// work to scale with count.
func buildRepeatedFieldQuery(count int) string {
	var builder strings.Builder

	builder.WriteString("{")

	for range count {
		builder.WriteString(`CVEListForImage(image:"repo:tag"){Tag}`)
	}

	builder.WriteString("}")

	return builder.String()
}

func TestSearchGQLResourceLimits(t *testing.T) {
	Convey("Search GraphQL endpoint enforces request budgets", t, func() {
		rootDir := t.TempDir()

		conf := config.New()
		conf.HTTP.Port = "0"
		conf.Storage.RootDirectory = rootDir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		ctlr := api.NewController(conf)
		if err := ctlr.Init(); err != nil {
			t.Fatal(err)
		}

		go func() {
			if err := ctlr.Run(); !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		}()

		defer ctlr.Shutdown()

		cm := NewControllerManager(ctlr)
		cm.WaitServerReady()
		baseURL := cm.BaseURL()

		Convey("a small, legitimate query is resolved normally", func() {
			resp, err := resty.R().
				SetHeader("Content-Type", "application/json").
				SetBody(map[string]string{"query": buildRepeatedFieldQuery(1)}).
				Post(baseURL + "/v2/_zot/ext/search")

			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			var result struct {
				Errors []struct {
					Message string `json:"message"`
				} `json:"errors"`
			}
			So(json.Unmarshal(resp.Body(), &result), ShouldBeNil)
			// CVE scanning isn't configured, so the resolver runs and returns its own,
			// expected error - proving the request reached resolution rather than being
			// rejected by a request budget.
			So(len(result.Errors), ShouldEqual, 1)
			So(result.Errors[0].Message, ShouldContainSubstring, "cve search is disabled")
		})

		Convey("a document with many repeated selections is rejected before resolution", func() {
			// Comfortably over searchParserTokenLimit (2000): each repetition is 8 tokens,
			// so 400 repetitions is ~3200 tokens.
			resp, err := resty.R().
				SetHeader("Content-Type", "application/json").
				SetBody(map[string]string{"query": buildRepeatedFieldQuery(400)}).
				Post(baseURL + "/v2/_zot/ext/search")

			So(err, ShouldBeNil)

			var result struct {
				Errors []struct {
					Message string `json:"message"`
				} `json:"errors"`
			}
			So(json.Unmarshal(resp.Body(), &result), ShouldBeNil)
			So(len(result.Errors), ShouldBeGreaterThan, 0)
			// Rejected at parse time, not at the resolver: the disabled-CVE message must not
			// appear, since that would mean every repeated field was individually resolved.
			for _, gqlErr := range result.Errors {
				So(gqlErr.Message, ShouldNotContainSubstring, "cve search is disabled")
			}
		})

		Convey("an oversized request body is rejected without being fully buffered", func() {
			oversized := strings.Repeat("a", 2*1024*1024) // 2 MiB, over MaxSearchBodySize (1 MiB)
			body := `{"query":"{CVEListForImage(image:\"repo:tag\"){Tag}}","extensions":{"padding":"` +
				oversized + `"}}`

			resp, err := resty.R().
				SetHeader("Content-Type", "application/json").
				SetHeader("Content-Length", strconv.Itoa(len(body))).
				SetBody(body).
				Post(baseURL + "/v2/_zot/ext/search")

			// A body-size rejection may close the connection instead of returning a well-formed
			// response; if that happens, assert it's a connection-close style error so an
			// unrelated failure (e.g. DNS, unreachable server) can't masquerade as a pass.
			if err != nil {
				msg := strings.ToLower(err.Error())
				isConnClose := strings.Contains(msg, "eof") || strings.Contains(msg, "connection reset") ||
					strings.Contains(msg, "broken pipe") || strings.Contains(msg, "closed network connection")
				So(isConnClose, ShouldBeTrue)

				return
			}

			// The handler still answers with its usual 200 + GraphQL error envelope (gqlgen's own
			// behavior), but the response is a short "body too large" error, not a resolved
			// CVEListForImage result - proving the oversized body was capped, not processed.
			So(len(resp.Body()), ShouldBeLessThan, 1024)

			var result struct {
				Errors []struct {
					Message string `json:"message"`
				} `json:"errors"`
			}
			So(json.Unmarshal(resp.Body(), &result), ShouldBeNil)
			So(len(result.Errors), ShouldBeGreaterThan, 0)

			for _, gqlErr := range result.Errors {
				So(gqlErr.Message, ShouldNotContainSubstring, "cve search is disabled")
			}
		})
	})
}
