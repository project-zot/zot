//go:build stress
// +build stress

package cli_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
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
	MaxFileDescriptors = 100
	WorkerRunningTime  = 60 * time.Second
)

func TestSressTooManyOpenFiles(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("configure zot with dedupe=false", t, func(c C) {
		// In case one of the So()-assertions will fail it will allow us to print
		// all the log files to figure out what happened in this test (zot log file, scrub output, storage rootFS tree)
		SetDefaultFailureMode(FailureContinues)

		initialLimit, err := setMaxOpenFilesLimit(MaxFileDescriptors)
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
				t.Logf("error when reading zot log file:\n%s\n", err)
			}
			t.Logf("\n\n Zot log file content:\n%s\n", string(data))
			os.Remove(logFile.Name())
		}()
		t.Log("Log file is: ", logFile.Name())
		conf.Log.Output = logFile.Name()

		ctlr := api.NewController(conf)
		dir := t.TempDir()

		defer func() {
			// list the content of the directory (useful in case of test fail)
			out, err := exec.Command("du", "-ab", dir).Output()
			if err != nil {
				t.Logf("error when listing storage files:\n%s\n", err)
			}
			t.Logf("Listing Storage root FS:\n%s\n", out)
		}()

		t.Log("Storage root dir is: ", dir)
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

		skopeoArgs := []string{
			"copy", "--format=oci", "--insecure-policy", "--dest-tls-verify=false",
			"docker://public.ecr.aws/zomato/alpine:3.11.3", fmt.Sprintf("oci:%s:alpine", dir),
		}
		out, err := exec.Command("skopeo", skopeoArgs...).Output()
		if err != nil {
			t.Logf("\nerror on skopeo copy:\n%s\n", err)
		}
		So(err, ShouldBeNil)
		t.Logf("\nCopy test image locally:\n%s\n", out)

		var wg sync.WaitGroup
		for i := 1; i <= MaxFileDescriptors; i++ {
			wg.Add(1)

			i := i

			go func() {
				defer wg.Done()
				worker(i, port, dir)
			}()
		}
		wg.Wait()

		_, err = setMaxOpenFilesLimit(initialLimit)
		So(err, ShouldBeNil)

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
				t.Logf("error when reading zot scrub file:\n%s\n", err)
			}
			t.Logf("\n\n Zot scrub file content:\n%s\n", string(data))
			os.Remove(scrubFile.Name())
		}()
		t.Log("Scrub file is: ", scrubFile.Name())

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
	start := time.Now()

	for i := 0; ; i++ {
		sourceImg := fmt.Sprintf("oci:%s:alpine", rootDir)
		destImg := fmt.Sprintf("docker://localhost:%s/client%d:%d", zotPort, id, i)

		skopeoArgs := []string{
			"copy", "--format=oci", "--insecure-policy", "--dest-tls-verify=false",
			sourceImg, destImg,
		}
		err := exec.Command("skopeo", skopeoArgs...).Run()
		if err != nil { // nolint: wsl
			continue // we expect clients to receive errors due to FD limit reached on server
		}

		time.Sleep(100 * time.Millisecond)
		end := time.Now()
		latency := end.Sub(start)

		if latency > WorkerRunningTime {
			break
		}
	}
}

func setMaxOpenFilesLimit(limit uint64) (uint64, error) {
	var rLimit syscall.Rlimit

	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return 0, err
	}

	fmt.Println("Current max. open files ", rLimit.Cur)
	initialLimit := rLimit.Cur
	rLimit.Cur = limit
	fmt.Println("Changing max. open files to ", limit)

	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return initialLimit, err
	}

	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return initialLimit, err
	}

	fmt.Println("Max. open files is set to", rLimit.Cur)

	return initialLimit, nil
}

func startServer(c *api.Controller) {
	// this blocks
	ctx := context.Background()
	if err := c.Run(ctx); err != nil {
		fmt.Printf("\nerror on starting zot server: %s\n", err)
	}
}

func stopServer(c *api.Controller) {
	ctx := context.Background()
	if err := c.Server.Shutdown(ctx); err != nil {
		fmt.Printf("\nerror on stopping zot server: %s\n", err)
	}
}
