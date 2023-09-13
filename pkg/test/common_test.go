//go:build sync && scrub && metrics && search
// +build sync,scrub,metrics,search

package test_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	notconfig "github.com/notaryproject/notation-go/config"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/test"
	. "zotregistry.io/zot/pkg/test/image-utils"
	"zotregistry.io/zot/pkg/test/inject"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("ErrTestError")

func TestCopyFiles(t *testing.T) {
	Convey("sourceDir does not exist", t, func() {
		err := test.CopyFiles("/path/to/some/unexisting/directory", os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("destDir is a file", t, func() {
		dir := t.TempDir()

		test.CopyTestFiles("../../test/data", dir)

		err := test.CopyFiles(dir, "/etc/passwd")
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir does not have read permissions", t, func() {
		dir := t.TempDir()

		err := os.Chmod(dir, 0o300)
		So(err, ShouldBeNil)

		err = test.CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir has a subfolder that does not have read permissions", t, func() {
		dir := t.TempDir()

		sdir := "subdir"
		err := os.Mkdir(path.Join(dir, sdir), 0o300)
		So(err, ShouldBeNil)

		err = test.CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir has a file that does not have read permissions", t, func() {
		dir := t.TempDir()

		filePath := path.Join(dir, "file.txt")
		err := os.WriteFile(filePath, []byte("some dummy file content"), 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = os.Chmod(filePath, 0o300)
		So(err, ShouldBeNil)

		err = test.CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir contains a folder starting with invalid characters", t, func() {
		srcDir := t.TempDir()
		dstDir := t.TempDir()

		err := os.MkdirAll(path.Join(srcDir, "_trivy", "db"), 0o755)
		if err != nil {
			panic(err)
		}

		err = os.MkdirAll(path.Join(srcDir, "test-index"), 0o755)
		if err != nil {
			panic(err)
		}

		filePathTrivy := path.Join(srcDir, "_trivy", "db", "trivy.db")
		err = os.WriteFile(filePathTrivy, []byte("some dummy file content"), 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		var index ispec.Index
		content, err := json.Marshal(index)
		if err != nil {
			panic(err)
		}

		err = os.WriteFile(path.Join(srcDir, "test-index", "index.json"), content, 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = test.CopyFiles(srcDir, dstDir)
		So(err, ShouldBeNil)

		_, err = os.Stat(path.Join(dstDir, "_trivy", "db", "trivy.db"))
		So(err, ShouldNotBeNil)
		So(os.IsNotExist(err), ShouldBeTrue)

		_, err = os.Stat(path.Join(dstDir, "test-index", "index.json"))
		So(err, ShouldBeNil)
	})
	Convey("panic when sourceDir does not exist", t, func() {
		So(func() { test.CopyTestFiles("/path/to/some/unexisting/directory", os.TempDir()) }, ShouldPanic)
	})
}

func TestGetImageComponents(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		injected := inject.InjectFailure(0)
		if injected {
			_, _, _, err := test.GetImageComponents(100)
			So(err, ShouldNotBeNil)
		}
	})
	Convey("finishes successfully", t, func() {
		_, _, _, err := test.GetImageComponents(100)
		So(err, ShouldBeNil)
	})
}

func TestGetRandomImageComponents(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		injected := inject.InjectFailure(0)
		if injected {
			_, _, _, err := test.GetRandomImageComponents(100)
			So(err, ShouldNotBeNil)
		}
	})
}

func TestGetImageComponentsWithConfig(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		injected := inject.InjectFailure(0)
		if injected {
			_, _, _, err := test.GetImageComponentsWithConfig(ispec.Image{})
			So(err, ShouldNotBeNil)
		}
	})
}

func TestWaitTillTrivyDBDownloadStarted(t *testing.T) {
	Convey("finishes successfully", t, func() {
		tempDir := t.TempDir()
		go func() {
			test.WaitTillTrivyDBDownloadStarted(tempDir)
		}()

		time.Sleep(test.SleepTime)

		_, err := os.Create(path.Join(tempDir, "trivy.db"))
		So(err, ShouldBeNil)
	})
}

func TestControllerManager(t *testing.T) {
	Convey("Test StartServer Init() panic", t, func() {
		port := test.GetFreePort()

		conf := config.New()
		conf.HTTP.Port = port

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		// No storage configured
		So(func() { ctlrManager.StartServer() }, ShouldPanic)
	})

	Convey("Test RunServer panic", t, func() {
		tempDir := t.TempDir()

		// Invalid port
		conf := config.New()
		conf.HTTP.Port = "999999"
		conf.Storage.RootDirectory = tempDir

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		ctx := context.Background()

		err := ctlr.Init(ctx)
		So(err, ShouldBeNil)

		So(func() { ctlrManager.RunServer(ctx) }, ShouldPanic)
	})
}

func TestReadLogFileAndSearchString(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
	if err != nil {
		panic(err)
	}

	logPath := logFile.Name()
	defer os.Remove(logPath)

	Convey("Invalid path", t, func() {
		_, err = test.ReadLogFileAndSearchString("invalidPath", "DB update completed, next update scheduled", 1*time.Second)
		So(err, ShouldNotBeNil)
	})

	Convey("Time too short", t, func() {
		ok, err := test.ReadLogFileAndSearchString(logPath, "invalid string", time.Microsecond)
		So(err, ShouldBeNil)
		So(ok, ShouldBeFalse)
	})
}

func TestReadLogFileAndCountStringOccurence(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
	if err != nil {
		panic(err)
	}

	_, err = logFile.Write([]byte("line1\n line2\n line3 line1 line2\n line1"))
	if err != nil {
		panic(err)
	}

	logPath := logFile.Name()
	defer os.Remove(logPath)

	Convey("Invalid path", t, func() {
		_, err = test.ReadLogFileAndCountStringOccurence("invalidPath",
			"DB update completed, next update scheduled", 1*time.Second, 1)
		So(err, ShouldNotBeNil)
	})

	Convey("Time too short", t, func() {
		ok, err := test.ReadLogFileAndCountStringOccurence(logPath, "invalid string", time.Microsecond, 1)
		So(err, ShouldBeNil)
		So(ok, ShouldBeFalse)
	})

	Convey("Count occurrence working", t, func() {
		ok, err := test.ReadLogFileAndCountStringOccurence(logPath, "line1", 90*time.Second, 3)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
	})
}

func TestCopyFile(t *testing.T) {
	Convey("destFilePath does not exist", t, func() {
		err := test.CopyFile("/path/to/srcFile", "~/path/to/some/unexisting/destDir/file")
		So(err, ShouldNotBeNil)
	})

	Convey("sourceFile does not exist", t, func() {
		err := test.CopyFile("/path/to/some/unexisting/file", path.Join(t.TempDir(), "destFile.txt"))
		So(err, ShouldNotBeNil)
	})
}

func TestIsDigestReference(t *testing.T) {
	Convey("not digest reference", t, func() {
		res := test.IsDigestReference("notDigestReference/input")
		So(res, ShouldBeFalse)
	})

	Convey("wrong input format", t, func() {
		res := test.IsDigestReference("wrongInput")
		So(res, ShouldBeFalse)
	})
}

func TestLoadNotationSigningkeys(t *testing.T) {
	Convey("notation directory doesn't exist", t, func() {
		_, err := test.LoadNotationSigningkeys(t.TempDir())
		So(err, ShouldNotBeNil)
	})

	Convey("wrong content of signingkeys.json", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(dir, "signingkeys.json")
		err = os.WriteFile(filePath, []byte("some dummy file content"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		_, err = test.LoadNotationSigningkeys(tempDir)
		So(err, ShouldNotBeNil)
	})

	Convey("not enough permissions to access signingkeys.json", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(dir, "signingkeys.json")
		err = os.WriteFile(filePath, []byte("some dummy file content"), 0o300) //nolint: gosec
		So(err, ShouldBeNil)

		_, err = test.LoadNotationSigningkeys(tempDir)
		So(err, ShouldNotBeNil)
	})

	Convey("signingkeys.json not exists so it is created successfully", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		_, err = test.LoadNotationSigningkeys(tempDir)
		So(err, ShouldBeNil)
	})

	Convey("signingkeys.json not exists - error trying to create it", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		// create notation directory without write permissions
		err := os.Mkdir(dir, 0o555)
		So(err, ShouldBeNil)

		_, err = test.LoadNotationSigningkeys(tempDir)
		So(err, ShouldNotBeNil)
	})
}

func TestLoadNotationConfig(t *testing.T) {
	Convey("directory doesn't exist", t, func() {
		_, err := test.LoadNotationConfig(t.TempDir())
		So(err, ShouldNotBeNil)
	})

	Convey("wrong content of signingkeys.json", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(dir, "signingkeys.json")
		err = os.WriteFile(filePath, []byte("some dummy file content"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		_, err = test.LoadNotationConfig(tempDir)
		So(err, ShouldNotBeNil)
	})

	Convey("check default value of signature format", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(dir, "signingkeys.json")
		err = os.WriteFile(filePath, []byte("{\"SignatureFormat\": \"\"}"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		configInfo, err := test.LoadNotationConfig(tempDir)
		So(err, ShouldBeNil)
		So(configInfo.SignatureFormat, ShouldEqual, "jws")
	})
}

func TestSignWithNotation(t *testing.T) {
	Convey("notation directory doesn't exist", t, func() {
		err := test.SignWithNotation("key", "reference", t.TempDir())
		So(err, ShouldNotBeNil)
	})

	Convey("key not found", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(dir, "signingkeys.json")
		err = os.WriteFile(filePath, []byte("{}"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		err = test.SignWithNotation("key", "reference", tempDir)
		So(err, ShouldEqual, test.ErrKeyNotFound)
	})

	Convey("not enough permissions to access notation/localkeys dir", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tdir)

		err = test.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = os.Chmod(path.Join(tdir, "notation", "localkeys"), 0o000)
		So(err, ShouldBeNil)

		err = test.SignWithNotation("key", "reference", tdir)
		So(err, ShouldNotBeNil)

		err = os.Chmod(path.Join(tdir, "notation", "localkeys"), 0o755)
		So(err, ShouldBeNil)
	})

	Convey("error parsing reference", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tdir)

		err = test.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = test.SignWithNotation("key", "invalidReference", tdir)
		So(err, ShouldNotBeNil)
	})

	Convey("error signing", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tdir)

		err = test.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = test.SignWithNotation("key", "localhost:8080/invalidreference:1.0", tdir)
		So(err, ShouldNotBeNil)
	})
}

func TestVerifyWithNotation(t *testing.T) {
	Convey("notation directory doesn't exist", t, func() {
		err := test.VerifyWithNotation("reference", t.TempDir())
		So(err, ShouldNotBeNil)
	})

	Convey("error parsing reference", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tdir)

		err = test.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = test.VerifyWithNotation("invalidReference", tdir)
		So(err, ShouldNotBeNil)
	})

	Convey("error trying to get manifest", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tdir)

		err = test.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = test.VerifyWithNotation("localhost:8080/invalidreference:1.0", tdir)
		So(err, ShouldNotBeNil)
	})

	Convey("invalid content of trustpolicy.json", t, func() {
		// start a new server
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		dir := t.TempDir()

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)
		// this blocks
		cm.StartAndWait(port)
		defer cm.StopServer()

		repoName := "signed-repo"
		tag := "1.0"
		cfg, layers, manifest, err := test.GetImageComponents(2)
		So(err, ShouldBeNil)

		err = UploadImage(
			Image{
				Config:   cfg,
				Layers:   layers,
				Manifest: manifest,
			}, baseURL, repoName, tag)
		So(err, ShouldBeNil)

		content, err := json.Marshal(manifest)
		So(err, ShouldBeNil)
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		tempDir := t.TempDir()
		notationDir := path.Join(tempDir, "notation")
		err = os.Mkdir(notationDir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(notationDir, "trustpolicy.json")
		err = os.WriteFile(filePath, []byte("some dummy file content"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.VerifyWithNotation(fmt.Sprintf("localhost:%s/%s:%s", port, repoName, tag), tempDir)
		So(err, ShouldNotBeNil)
	})
}

func TestListNotarySignatures(t *testing.T) {
	Convey("error parsing reference", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		_, err = test.ListNotarySignatures("invalidReference", tdir)
		So(err, ShouldNotBeNil)
	})

	Convey("error trying to get manifest", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		_, err = test.ListNotarySignatures("localhost:8080/invalidreference:1.0", tdir)
		So(err, ShouldNotBeNil)
	})
}

func TestGenerateNotationCerts(t *testing.T) {
	Convey("write key file with permission", t, func() {
		tempDir := t.TempDir()

		notationDir := path.Join(tempDir, "notation")
		err := os.Mkdir(notationDir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(notationDir, "localkeys")
		err = os.WriteFile(filePath, []byte("{}"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.GenerateNotationCerts(t.TempDir(), "cert")
		So(err, ShouldNotBeNil)
	})

	Convey("write cert file with permission", t, func() {
		tempDir := t.TempDir()

		notationDir := path.Join(tempDir, "notation", "localkeys")
		err := os.MkdirAll(notationDir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(notationDir, "cert.crt")
		err = os.WriteFile(filePath, []byte("{}"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		err = os.Chmod(filePath, 0o000)
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.GenerateNotationCerts(t.TempDir(), "cert")
		So(err, ShouldNotBeNil)

		err = os.Chmod(filePath, 0o755)
		So(err, ShouldBeNil)
	})

	Convey("signingkeys.json file - not enough permission", t, func() {
		tempDir := t.TempDir()

		notationDir := path.Join(tempDir, "notation")
		err := os.Mkdir(notationDir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(notationDir, "signingkeys.json")
		_, err = os.Create(filePath) //nolint: gosec
		So(err, ShouldBeNil)
		err = os.Chmod(filePath, 0o000)
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.GenerateNotationCerts(t.TempDir(), "cert")
		So(err, ShouldNotBeNil)

		err = os.Remove(filePath)
		So(err, ShouldBeNil)
		err = os.RemoveAll(path.Join(notationDir, "localkeys"))
		So(err, ShouldBeNil)
		signingKeysBuf, err := json.Marshal(notconfig.SigningKeys{})
		So(err, ShouldBeNil)
		err = os.WriteFile(filePath, signingKeysBuf, 0o555) //nolint:gosec // test code
		So(err, ShouldBeNil)
		err = test.GenerateNotationCerts(t.TempDir(), "cert")
		So(err, ShouldNotBeNil)
	})
	Convey("keysuite already exists in signingkeys.json", t, func() {
		tempDir := t.TempDir()

		notationDir := path.Join(tempDir, "notation")
		err := os.Mkdir(notationDir, 0o777)
		So(err, ShouldBeNil)

		certName := "cert-test"
		filePath := path.Join(notationDir, "signingkeys.json")
		keyPath := path.Join(notationDir, "localkeys", certName+".key")
		certPath := path.Join(notationDir, "localkeys", certName+".crt")
		signingKeys := notconfig.SigningKeys{}
		keySuite := notconfig.KeySuite{
			Name: certName,
			X509KeyPair: &notconfig.X509KeyPair{
				KeyPath:         keyPath,
				CertificatePath: certPath,
			},
		}
		signingKeys.Keys = []notconfig.KeySuite{keySuite}
		signingKeysBuf, err := json.Marshal(signingKeys)
		So(err, ShouldBeNil)
		err = os.WriteFile(filePath, signingKeysBuf, 0o600)
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.GenerateNotationCerts(t.TempDir(), certName)
		So(err, ShouldNotBeNil)
	})
	Convey("truststore files", t, func() {
		tempDir := t.TempDir()

		notationDir := path.Join(tempDir, "notation")
		err := os.Mkdir(notationDir, 0o777)
		So(err, ShouldBeNil)

		certName := "cert-test"
		trustStorePath := path.Join(notationDir, fmt.Sprintf("truststore/x509/ca/%s", certName))
		err = os.MkdirAll(trustStorePath, 0o755)
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(notationDir, "truststore/x509"), 0o000)
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.GenerateNotationCerts(tempDir, certName)
		So(err, ShouldNotBeNil)

		err = os.RemoveAll(path.Join(notationDir, "localkeys"))
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(notationDir, "truststore/x509"), 0o755)
		So(err, ShouldBeNil)
		_, err = os.Create(path.Join(trustStorePath, "cert-test.crt"))
		So(err, ShouldBeNil)

		err = test.GenerateNotationCerts(tempDir, certName)
		So(err, ShouldNotBeNil)

		err = os.RemoveAll(path.Join(notationDir, "localkeys"))
		So(err, ShouldBeNil)
		err = os.Remove(path.Join(trustStorePath, "cert-test.crt"))
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(notationDir, "truststore/x509/ca", certName), 0o555)
		So(err, ShouldBeNil)

		err = test.GenerateNotationCerts(tempDir, certName)
		So(err, ShouldNotBeNil)
	})
}

func TestWriteImageToFileSystem(t *testing.T) {
	Convey("WriteImageToFileSystem errors", t, func() {
		err := test.WriteImageToFileSystem(Image{}, "repo", "dig", storage.StoreController{
			DefaultStore: mocks.MockedImageStore{
				InitRepoFn: func(name string) error {
					return ErrTestError
				},
			},
		})
		So(err, ShouldNotBeNil)

		err = test.WriteImageToFileSystem(
			Image{Layers: [][]byte{[]byte("testLayer")}},
			"repo",
			"tag",
			storage.StoreController{
				DefaultStore: mocks.MockedImageStore{
					FullBlobUploadFn: func(repo string, body io.Reader, digest godigest.Digest,
					) (string, int64, error) {
						return "", 0, ErrTestError
					},
				},
			})
		So(err, ShouldNotBeNil)

		count := 0
		err = test.WriteImageToFileSystem(
			Image{Layers: [][]byte{[]byte("testLayer")}},
			"repo",
			"tag",
			storage.StoreController{
				DefaultStore: mocks.MockedImageStore{
					FullBlobUploadFn: func(repo string, body io.Reader, digest godigest.Digest,
					) (string, int64, error) {
						if count == 0 {
							count++

							return "", 0, nil
						}

						return "", 0, ErrTestError
					},
				},
			})
		So(err, ShouldNotBeNil)

		err = test.WriteImageToFileSystem(
			Image{Layers: [][]byte{[]byte("testLayer")}},
			"repo",
			"tag",
			storage.StoreController{
				DefaultStore: mocks.MockedImageStore{
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte,
					) (godigest.Digest, godigest.Digest, error) {
						return "", "", ErrTestError
					},
				},
			})
		So(err, ShouldNotBeNil)
	})
}

func TestBearerServer(t *testing.T) {
	Convey("test MakeAuthTestServer() no serve key", t, func() {
		So(func() { test.MakeAuthTestServer("", "") }, ShouldPanic)
	})
}

func TestCopyTestKeysAndCerts(t *testing.T) {
	Convey("CopyTestKeysAndCerts", t, func() {
		// ------- Make test files unreadable -------
		dir := t.TempDir()
		file := filepath.Join(dir, "ca.crt")

		_, err := os.Create(file)
		So(err, ShouldBeNil)

		err = os.Chmod(file, 0o000)
		So(err, ShouldBeNil)

		err = test.CopyTestKeysAndCerts(dir)
		So(err, ShouldNotBeNil)

		err = os.Chmod(file, 0o777)
		So(err, ShouldBeNil)

		// ------- Copy fails -------

		err = os.Chmod(dir, 0o000)
		So(err, ShouldBeNil)

		err = test.CopyTestKeysAndCerts(file)
		So(err, ShouldNotBeNil)

		err = os.Chmod(dir, 0o777)
		So(err, ShouldBeNil)

		// ------- Folder creation fails -------

		file = filepath.Join(dir, "a-file.file")
		_, err = os.Create(file)
		So(err, ShouldBeNil)

		_, err = os.Stat(file)
		So(err, ShouldBeNil)

		err = test.CopyTestKeysAndCerts(file)
		So(err, ShouldNotBeNil)
	})
}
