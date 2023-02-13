//go:build search
// +build search

package extensions

import (
	"net/http"
	"sync"
	"time"

	gqlHandler "github.com/99designs/gqlgen/graphql/handler"
	"github.com/gorilla/mux"
	distext "github.com/opencontainers/distribution-spec/specs-go/v1/extensions"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/extensions/search"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/scheduler"
	"zotregistry.io/zot/pkg/storage"
)

type (
	CveInfo cveinfo.CveInfo
	state   int
)

const (
	pending state = iota
	running
	done
)

func GetCVEInfo(config *config.Config, storeController storage.StoreController,
	repoDB repodb.RepoDB, log log.Logger,
) CveInfo {
	if config.Extensions.Search == nil || !*config.Extensions.Search.Enable || config.Extensions.Search.CVE == nil {
		return nil
	}

	dbRepository := ""

	if config.Extensions.Search.CVE.Trivy != nil {
		dbRepository = config.Extensions.Search.CVE.Trivy.DBRepository
	}

	return cveinfo.NewCVEInfo(storeController, repoDB, dbRepository, log)
}

func EnableSearchExtension(config *config.Config, storeController storage.StoreController,
	repoDB repodb.RepoDB, taskScheduler *scheduler.Scheduler, cveInfo CveInfo, log log.Logger,
) {
	if config.Extensions.Search != nil && *config.Extensions.Search.Enable && config.Extensions.Search.CVE != nil {
		defaultUpdateInterval, _ := time.ParseDuration("2h")

		if config.Extensions.Search.CVE.UpdateInterval < defaultUpdateInterval {
			config.Extensions.Search.CVE.UpdateInterval = defaultUpdateInterval

			log.Warn().Msg("CVE update interval set to too-short interval < 2h, changing update duration to 2 hours and continuing.") //nolint:lll // gofumpt conflicts with lll
		}

		updateInterval := config.Extensions.Search.CVE.UpdateInterval

		downloadTrivyDB(updateInterval, taskScheduler, cveInfo, log)
	} else {
		log.Info().Msg("CVE config not provided, skipping CVE update")
	}
}

func downloadTrivyDB(interval time.Duration, sch *scheduler.Scheduler, cveInfo CveInfo, log log.Logger) {
	generator := &trivyTaskGenerator{interval, cveInfo, log, pending, 0, time.Now(), &sync.Mutex{}}

	sch.SubmitGenerator(generator, interval, scheduler.HighPriority)
}

type trivyTaskGenerator struct {
	interval     time.Duration
	cveInfo      CveInfo
	log          log.Logger
	status       state
	waitTime     time.Duration
	lastTaskTime time.Time
	lock         *sync.Mutex
}

func (gen *trivyTaskGenerator) GenerateTask() (scheduler.Task, error) {
	var newTask scheduler.Task

	gen.lock.Lock()

	if gen.status != running && time.Since(gen.lastTaskTime) >= gen.waitTime {
		newTask = newTrivyTask(gen.interval, gen.cveInfo, gen, gen.log)
		gen.status = running
	}
	gen.lock.Unlock()

	return newTask, nil
}

func (gen *trivyTaskGenerator) IsDone() bool {
	gen.lock.Lock()
	status := gen.status
	gen.lock.Unlock()

	return status == done
}

func (gen *trivyTaskGenerator) Reset() {
	gen.lock.Lock()
	gen.status = pending
	gen.waitTime = 0
	gen.lock.Unlock()
}

type trivyTask struct {
	interval  time.Duration
	cveInfo   cveinfo.CveInfo
	generator *trivyTaskGenerator
	log       log.Logger
}

func newTrivyTask(interval time.Duration, cveInfo cveinfo.CveInfo,
	generator *trivyTaskGenerator, log log.Logger,
) *trivyTask {
	return &trivyTask{interval, cveInfo, generator, log}
}

func (trivyT *trivyTask) DoWork() error {
	trivyT.log.Info().Msg("updating the CVE database")

	err := trivyT.cveInfo.UpdateDB()
	if err != nil {
		trivyT.generator.lock.Lock()
		trivyT.generator.status = pending
		trivyT.generator.waitTime += time.Second
		trivyT.generator.lastTaskTime = time.Now()
		trivyT.generator.lock.Unlock()

		return err
	}

	trivyT.generator.lock.Lock()
	trivyT.generator.lastTaskTime = time.Now()
	trivyT.generator.status = done
	trivyT.generator.lock.Unlock()
	trivyT.log.Info().Str("DB update completed, next update scheduled after", trivyT.interval.String()).Msg("")

	return nil
}

func addSearchSecurityHeaders(h http.Handler) http.HandlerFunc { //nolint:varnamelen
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")

		h.ServeHTTP(w, r)
	}
}

func SetupSearchRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	repoDB repodb.RepoDB, cveInfo CveInfo, log log.Logger,
) {
	log.Info().Msg("setting up search routes")

	if config.Extensions.Search != nil && *config.Extensions.Search.Enable {
		resConfig := search.GetResolverConfig(log, storeController, repoDB, cveInfo)

		extRouter := router.PathPrefix(constants.ExtSearchPrefix).Subrouter()
		extRouter.Methods("GET", "POST", "OPTIONS").
			Handler(addSearchSecurityHeaders(gqlHandler.NewDefaultServer(gql_generated.NewExecutableSchema(resConfig))))
	}
}

func getExtension(name, url, description string, endpoints []string) distext.Extension {
	return distext.Extension{
		Name:        name,
		URL:         url,
		Description: description,
		Endpoints:   endpoints,
	}
}

func GetExtensions(config *config.Config) distext.ExtensionList {
	extensionList := distext.ExtensionList{}

	extensions := make([]distext.Extension, 0)

	if config.Extensions != nil && config.Extensions.Search != nil {
		endpoints := []string{constants.FullSearchPrefix}
		searchExt := getExtension("_zot",
			"https://github.com/project-zot/zot/blob/"+config.ReleaseTag+"/pkg/extensions/_zot.md",
			"zot registry extensions",
			endpoints)

		extensions = append(extensions, searchExt)
	}

	if config.Extensions != nil && config.Extensions.Mgmt != nil {
		endpoints := []string{constants.FullMgmtPrefix}
		mgmtExt := getExtension("_zot",
			"https://github.com/project-zot/zot/blob/"+config.ReleaseTag+"/pkg/extensions/_zot.md",
			"zot registry extensions",
			endpoints)

		extensions = append(extensions, mgmtExt)
	}

	extensionList.Extensions = extensions

	return extensionList
}
