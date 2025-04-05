//go:build !events
// +build !events

package events_test

import (
	"bytes"
	goContext "context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	eventsconf "zotregistry.dev/zot/pkg/extensions/config/events"
	"zotregistry.dev/zot/pkg/extensions/events"
	test "zotregistry.dev/zot/pkg/test/common"
)

func TestEventsExtension(t *testing.T) {
	Convey("verify events are logged", t, func() {
		conf := config.New()
		port := test.GetFreePort()

		baseURL := test.GetBaseURL(port)
		globalDir := t.TempDir()
		defaultValue := true

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		So(err, ShouldBeNil)
		defer os.Remove(logFile.Name())

		conf.HTTP.Port = port
		conf.Storage.RootDirectory = globalDir
		conf.Storage.Commit = true
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Events = &eventsconf.Config{
			Enable: &defaultValue,
		}
		conf.Log.Level = "debug"
		conf.Log.Output = logFile.Name()

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		routeHandler := api.NewRouteHandler(ctlr)

		Convey("repository created event", func() {
			str := []byte("test")
			urlVars := map[string]string{
				"name":      "test",
				"reference": "reference",
			}
			request, _ := http.NewRequestWithContext(goContext.Background(), http.MethodPut, baseURL, bytes.NewBuffer(str))
			request = mux.SetURLVars(request, urlVars)
			request.Header.Add("Content-Type", ispec.MediaTypeImageManifest)
			response := httptest.NewRecorder()

			routeHandler.UpdateManifest(response, request)

			resp := response.Result()
			defer resp.Body.Close()

			data, err := os.ReadFile(logFile.Name())
			So(err, ShouldBeNil)

			So(string(data), ShouldContainSubstring, events.RepositoryCreatedEventType.String())
		})
	})
}
