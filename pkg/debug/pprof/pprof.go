//go:build profile
// +build profile

package pprof

import (
	"bytes"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/pprof"
	"net/url"
	runPprof "runtime/pprof"
	"sort"
	"strings"

	"github.com/gorilla/mux"

	"zotregistry.dev/zot/pkg/api/config"
	registryConst "zotregistry.dev/zot/pkg/api/constants"
	zcommon "zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/debug/constants"
	"zotregistry.dev/zot/pkg/log"
)

type profileEntry struct {
	Name  string
	Href  string
	Desc  string
	Count int
}

var profileDescriptions = map[string]string{ //nolint: gochecknoglobals
	"allocs":       "A sampling of all past memory allocations",
	"block":        "Stack traces that led to blocking on synchronization primitives",
	"cmdline":      "The command line invocation of the current program",
	"goroutine":    "Stack traces of all current goroutines. Use debug=2 as a query parameter to export in the same format as an unrecovered panic.",  //nolint: lll
	"heap":         "A sampling of memory allocations of live objects. You can specify the gc GET parameter to run GC before taking the heap sample.", //nolint: lll
	"mutex":        "Stack traces of holders of contended mutexes",
	"profile":      "CPU profile. You can specify the duration in the seconds GET parameter. After you get the profile file, use the go tool pprof command to investigate the profile.", //nolint: lll
	"threadcreate": "Stack traces that led to the creation of new OS threads",
	"trace":        "A trace of execution of the current program. You can specify the duration in the seconds GET parameter. After you get the trace file, use the go tool trace command to investigate the trace.", //nolint: lll
}

func SetupPprofRoutes(conf *config.Config, router *mux.Router, authFunc mux.MiddlewareFunc,
	log log.Logger,
) {
	// If authn/authz are enabled the endpoints for pprof should be available only to admins
	pprofRouter := router.PathPrefix(constants.ProfilingEndpoint).Subrouter()
	pprofRouter.Use(zcommon.AuthzOnlyAdminsMiddleware(conf))
	pprofRouter.Methods(http.MethodGet).Handler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if name, found := strings.CutPrefix(r.URL.Path,
				registryConst.RoutePrefix+constants.ProfilingEndpoint); found {
				if name != "" {
					switch name {
					case "profile": // not available through pprof.Handler
						pprof.Profile(w, r)

						return
					case "trace": // not available through pprof.Handler
						pprof.Trace(w, r)

						return
					default:
						pprof.Handler(name).ServeHTTP(w, r)

						return
					}
				}
			}

			var profiles []profileEntry
			for _, p := range runPprof.Profiles() {
				profiles = append(profiles, profileEntry{
					Name:  p.Name(),
					Href:  p.Name(),
					Desc:  profileDescriptions[p.Name()],
					Count: p.Count(),
				})
			}

			// Adding other profiles exposed from within this package
			for _, p := range []string{"cmdline", "profile", "trace"} {
				profiles = append(profiles, profileEntry{
					Name: p,
					Href: p,
					Desc: profileDescriptions[p],
				})
			}

			sort.Slice(profiles, func(i, j int) bool {
				return profiles[i].Name < profiles[j].Name
			})

			if err := indexTmplExecute(w, profiles); err != nil {
				log.Print(err)
			}
		}))
}

func indexTmplExecute(writer io.Writer, profiles []profileEntry) error {
	var buff bytes.Buffer

	buff.WriteString(`<html>
<head>
<title>/v2/_zot/pprof/</title>
<style>
.profile-name{
	display:inline-block;
	width:6rem;
}
</style>
</head>
<body>
/debug/pprof/
<br>
<p>Set debug=1 as a query parameter to export in legacy text format</p>
<br>
Types of profiles available:
<table>
<thead><td>Count</td><td>Profile</td></thead>
`)

	for _, profile := range profiles {
		link := &url.URL{Path: profile.Href, RawQuery: "debug=1"}
		fmt.Fprintf(&buff, "<tr><td>%d</td><td><a href='%s'>%s</a></td></tr>\n",
			profile.Count, link, html.EscapeString(profile.Name))
	}

	buff.WriteString(`</table>
<a href="goroutine?debug=2">full goroutine stack dump</a>
<br>
<p>
Profile Descriptions:
<ul>
`)

	for _, profile := range profiles {
		fmt.Fprintf(&buff, "<li><div class=profile-name>%s: </div> %s</li>\n",
			html.EscapeString(profile.Name), html.EscapeString(profile.Desc))
	}

	buff.WriteString(`</ul>
</p>
</body>
</html>`)

	_, err := writer.Write(buff.Bytes())

	return err
}
