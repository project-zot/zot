//go:build search

package cveinfo_test

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	cveinfo "zotregistry.dev/zot/v2/pkg/extensions/search/cve"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestCVEDBGenerator(t *testing.T) {
	Convey("Test CVE DB task scheduler reset", t, func() {
		logFile := test.MakeTempFile(t, "zot-log.txt")
		defer logFile.Close()

		logPath := logFile.Name()

		writers := io.MultiWriter(os.Stdout, logFile)
		logger := log.NewLoggerWithWriter("debug", writers)

		cfg := config.New()
		cfg.Scheduler = &config.SchedulerConfig{NumWorkers: 3}
		metrics := monitoring.NewMetricsServer(true, logger)
		sch := scheduler.NewScheduler(cfg, metrics, logger)

		metaDB := &mocks.MetaDBMock{
			GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
				return mTypes.RepoMeta{
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"tag": {MediaType: ispec.MediaTypeImageIndex},
					},
				}, nil
			},
		}
		storeController := storage.StoreController{
			DefaultStore: mocks.MockedImageStore{
				RootDirFn: func() string {
					return t.TempDir()
				},
			},
		}

		cveScanner := cveinfo.NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db", "", logger)
		generator := cveinfo.NewDBUpdateTaskGenerator(time.Minute, cveScanner, logger)

		sch.SubmitGenerator(generator, 12000*time.Millisecond, scheduler.HighPriority)

		sch.RunScheduler()

		defer sch.Shutdown()

		// Wait for trivy db to download
		found, err := test.ReadLogFileAndCountStringOccurence(logPath,
			"cve-db update completed, next update scheduled after interval", 240*time.Second, 2)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)
	})
}
