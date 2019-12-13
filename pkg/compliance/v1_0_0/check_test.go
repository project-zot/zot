package v1_0_0_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/anuvu/zot/pkg/api"
	"github.com/anuvu/zot/pkg/compliance"
	"github.com/anuvu/zot/pkg/compliance/v1_0_0"
	"gopkg.in/resty.v1"
)

const (
	Address = "127.0.0.1"
	Port    = "8080"
)

func TestWorkflows(t *testing.T) {
	v1_0_0.CheckWorkflows(t, &compliance.Config{Address: Address, Port: Port})
}

func TestMain(m *testing.M) {
	config := api.NewConfig()
	config.HTTP.Address = Address
	config.HTTP.Port = Port
	c := api.NewController(config)
	dir, err := ioutil.TempDir("", "oci-repo-test")

	if err != nil {
		panic(err)
	}
	//defer os.RemoveAll(dir)
	c.Config.Storage.RootDirectory = dir

	go func() {
		// this blocks
		if err := c.Run(); err != nil {
			return
		}
	}()

	BaseURL := fmt.Sprintf("http://%s:%s", Address, Port)

	for {
		// poll until ready
		resp, _ := resty.R().Get(BaseURL)
		if resp.StatusCode() == 404 {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	status := m.Run()
	ctx := context.Background()
	_ = c.Server.Shutdown(ctx)

	os.Exit(status)
}
