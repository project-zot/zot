package v1_0_0_test

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/compliance"
	"zotregistry.dev/zot/pkg/compliance/v1_0_0"
	. "zotregistry.dev/zot/pkg/test/common"
)

//nolint:gochecknoglobals
var (
	listenAddress = "127.0.0.1"
	defaultDir    = ""
	firstDir      = ""
	secondDir     = ""
)

func TestWorkflows(t *testing.T) {
	ctrl, randomPort := startServer(t)
	defer stopServer(ctrl)

	storageInfo := []string{defaultDir, firstDir, secondDir}

	v1_0_0.CheckWorkflows(t, &compliance.Config{
		Address:     listenAddress,
		Port:        randomPort,
		StorageInfo: storageInfo,
	})
}

func TestWorkflowsOutputJSON(t *testing.T) {
	ctrl, randomPort := startServer(t)
	defer stopServer(ctrl)

	storageInfo := []string{defaultDir, firstDir, secondDir}

	v1_0_0.CheckWorkflows(t, &compliance.Config{
		Address:     listenAddress,
		Port:        randomPort,
		OutputJSON:  true,
		StorageInfo: storageInfo,
	})
}

// start local server on random open port.
func startServer(t *testing.T) (*api.Controller, string) {
	t.Helper()

	port := GetFreePort()
	baseURL := GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Address = listenAddress
	conf.HTTP.Port = port
	ctrl := api.NewController(conf)

	dir := t.TempDir()
	defaultDir = dir

	firstSubDir := t.TempDir()
	firstDir = firstSubDir

	secondSubDir := t.TempDir()
	secondDir = secondSubDir

	subPaths := make(map[string]config.StorageConfig)

	subPaths["/firsttest"] = config.StorageConfig{RootDirectory: firstSubDir}
	subPaths["/secondtest"] = config.StorageConfig{RootDirectory: secondSubDir}

	ctrl.Config.Storage.RootDirectory = dir

	ctrl.Config.Storage.SubPaths = subPaths

	go func() {
		if err := ctrl.Init(); err != nil {
			return
		}

		// this blocks
		if err := ctrl.Run(); err != nil {
			return
		}
	}()

	for {
		// poll until ready
		resp, _ := resty.R().Get(baseURL)
		if resp.StatusCode() == http.StatusNotFound {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	return ctrl, port
}

func stopServer(ctrl *api.Controller) {
	err := ctrl.Server.Shutdown(context.Background())
	if err != nil {
		panic(err)
	}

	err = os.RemoveAll(ctrl.Config.Storage.RootDirectory)
	if err != nil {
		panic(err)
	}
}
