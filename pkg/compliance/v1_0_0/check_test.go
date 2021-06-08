package v1_0_0_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/anuvu/zot/pkg/api"
	"github.com/anuvu/zot/pkg/api/config"
	"github.com/anuvu/zot/pkg/compliance"
	"github.com/anuvu/zot/pkg/compliance/v1_0_0"
	"github.com/phayes/freeport"
	"gopkg.in/resty.v1"
)

// nolint: gochecknoglobals
var (
	listenAddress = "127.0.0.1"
	defaultDir    = ""
	firstDir      = ""
	secondDir     = ""
)

func TestWorkflows(t *testing.T) {
	ctrl, randomPort := startServer()
	defer stopServer(ctrl)

	storageInfo := []string{defaultDir, firstDir, secondDir}

	v1_0_0.CheckWorkflows(t, &compliance.Config{
		Address:     listenAddress,
		Port:        randomPort,
		StorageInfo: storageInfo,
	})
}

func TestWorkflowsOutputJSON(t *testing.T) {
	ctrl, randomPort := startServer()
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
func startServer() (*api.Controller, string) {
	portInt, err := freeport.GetFreePort()
	if err != nil {
		panic(err)
	}

	randomPort := fmt.Sprintf("%d", portInt)
	fmt.Println(randomPort)

	conf := config.New()
	conf.HTTP.Address = listenAddress
	conf.HTTP.Port = randomPort
	ctrl := api.NewController(conf)

	dir, err := ioutil.TempDir("", "oci-repo-test")
	if err != nil {
		panic(err)
	}

	defaultDir = dir

	firstSubDir, err := ioutil.TempDir("", "oci-repo-test")
	if err != nil {
		panic(err)
	}

	firstDir = firstSubDir

	secondSubDir, err := ioutil.TempDir("", "oci-repo-test")
	if err != nil {
		panic(err)
	}

	secondDir = secondSubDir

	subPaths := make(map[string]config.StorageConfig)

	subPaths["/firsttest"] = config.StorageConfig{RootDirectory: firstSubDir}
	subPaths["/secondtest"] = config.StorageConfig{RootDirectory: secondSubDir}

	ctrl.Config.Storage.RootDirectory = dir

	ctrl.Config.Storage.SubPaths = subPaths

	go func() {
		// this blocks
		if err := ctrl.Run(); err != nil {
			return
		}
	}()

	baseURL := fmt.Sprintf("http://%s:%s", listenAddress, randomPort)

	for {
		// poll until ready
		resp, _ := resty.R().Get(baseURL)
		if resp.StatusCode() == 404 {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	return ctrl, randomPort
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
