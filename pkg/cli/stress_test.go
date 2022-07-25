//go:build stress
// +build stress

package cli_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/cli"
	"zotregistry.io/zot/pkg/test"
)

const (
	MaxFileDescriptors = 512
	WorkerRunningTime  = 60 * time.Second
)

func TestSressTooManyOpenFiles(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("configure zot with dedupe=false", t, func(c C) {
		// In case one of the So()-assertions will fail it will allow us to print
		// all the log files to figure out what happened in this test (zot log file, scrub output, storage rootFS tree)
		SetDefaultFailureMode(FailureContinues)

		err := setMaxOpenFilesLimit(MaxFileDescriptors)
		So(err, ShouldBeNil)

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.Dedupe = false
		conf.Storage.GC = true

		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer func() {
			data, err := os.ReadFile(logFile.Name())
			if err != nil {
				fmt.Printf("error when reading zot log file:\n%s\n", err)
			}
			fmt.Printf("\n\n Zot log file content:\n%s\n", string(data))
			os.Remove(logFile.Name())
		}()
		fmt.Println("Log file is: ", logFile.Name())
		conf.Log.Output = logFile.Name()

		ctlr := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}

		defer func() {
			// list the content of the directory (useful in case of test fail)
			cmd := fmt.Sprintf("du -ab %s", dir)
			out, err := exec.Command("bash", "-c", cmd).Output()
			if err != nil {
				fmt.Printf("error when listing storage files:\n%s\n", err)
			}
			fmt.Printf("Listing Storage root FS:\n%s\n", out)
			os.RemoveAll(dir)
		}()

		fmt.Println("Storage root dir is: ", dir)
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		test.WaitTillServerReady(baseURL)
		content := fmt.Sprintf(`{
				"storage": {
					"rootDirectory": "%s",
					"dedupe": %t,
					"gc": %t
				},
				"http": {
					"address": "127.0.0.1",
					"port": "%s"
				},
				"log": {
					"level": "debug",
					"output": "%s"
				}
			}`, dir, conf.Storage.Dedupe, conf.Storage.GC, port, logFile.Name())

		cfgfile, err := ioutil.TempFile("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(cfgfile.Name()) // clean up
		_, err = cfgfile.Write([]byte(content))
		So(err, ShouldBeNil)
		err = cfgfile.Close()
		So(err, ShouldBeNil)

		args := []string{
			"copy", "--format=oci", "--dest-tls-verify=false", "--insecure-policy",
			"docker://public.ecr.aws/zomato/alpine:3.11.3", path.Join("dir:", dir, "/alpine"),
		}
		out, err := exec.Command("skopeo", args...).Output()
		if err != nil {
			fmt.Printf("\nCopy skopeo docker image:\n%s\n", out)
			fmt.Printf("\nerror on skopeo copy:\n%s\n", err)
		}

		So(err, ShouldBeNil)

		var wg sync.WaitGroup
		for i := 1; i <= MaxFileDescriptors; i++ {
			wg.Add(1)

			i := i

			go func() {
				defer wg.Done()
				t.Logf("i is %d, port is %s", i, port)
				worker(i, port, dir)
			}()
		}
		wg.Wait()

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "too many open files")

		stopServer(ctlr)
		time.Sleep(2 * time.Second)

		scrubFile, err := ioutil.TempFile("", "zot-scrub*.txt")
		So(err, ShouldBeNil)

		defer func() {
			data, err := os.ReadFile(scrubFile.Name())
			if err != nil {
				fmt.Printf("error when reading zot scrub file:\n%s\n", err)
			}
			fmt.Printf("\n\n Zot scrub file content:\n%s\n", string(data))
			os.Remove(scrubFile.Name())
		}()
		fmt.Println("Scrub file is: ", scrubFile.Name())

		os.Args = []string{"cli_test", "scrub", cfgfile.Name()}
		cobraCmd := cli.NewServerRootCmd()
		cobraCmd.SetOut(scrubFile)
		err = cobraCmd.Execute()
		So(err, ShouldBeNil)

		data, err = os.ReadFile(scrubFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldNotContainSubstring, "affected")
	})
}

func worker(id int, zotPort, rootDir string) {
	for i := 0; i < 6; i++ {
		args := []string{
			"copy", "--format=oci", "--dest-tls-verify=false", "--insecure-policy",
			path.Join("dir:", rootDir, "/alpine"),
			strings.Join([]string{"docker://localhost:", zotPort, "/client", fmt.Sprintf("%d", id), ":", fmt.Sprintf("%d", id)}, ""),
		}
		_ = exec.Command("skopeo", args...).Start()
	}
}

func setMaxOpenFilesLimit(limit uint64) error {
	var rLimit syscall.Rlimit

	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return err
	}

	fmt.Println("Current max. open files ", rLimit.Cur)
	rLimit.Cur = limit
	fmt.Println("Changing max. open files to ", limit)

	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return err
	}

	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return err
	}

	fmt.Println("Max. open files is set to", rLimit.Cur)

	return nil
}

func startServer(c *api.Controller) {
	// this blocks
	ctx := context.Background()
	if err := c.Run(ctx); err != nil {
		return
	}
}

func stopServer(c *api.Controller) {
	ctx := context.Background()
	_ = c.Server.Shutdown(ctx)
}
