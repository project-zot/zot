package v1_0_0_test

import (
	"context"
	"os"
	"strconv"
	"testing"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/compliance"
	"zotregistry.dev/zot/v2/pkg/compliance/v1_0_0"
	. "zotregistry.dev/zot/v2/pkg/test/common"
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

// start local server on a kernel-chosen port.
func startServer(t *testing.T) (*api.Controller, string) {
	t.Helper()

	conf := config.New()
	conf.HTTP.Address = listenAddress
	conf.HTTP.Port = "0"
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

	cm := NewControllerManager(ctrl)
	_ = cm.StartAndWait()

	port := strconv.Itoa(cm.Port())

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
