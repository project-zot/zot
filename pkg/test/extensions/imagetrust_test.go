//go:build sync && scrub && metrics && search
// +build sync,scrub,metrics,search

package extensions_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"testing"

	notconfig "github.com/notaryproject/notation-go/config"
	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/test"
	extt "zotregistry.io/zot/pkg/test/extensions"
)

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
		_, err := extt.LoadNotationSigningkeys(t.TempDir())
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

		_, err = extt.LoadNotationSigningkeys(tempDir)
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

		_, err = extt.LoadNotationSigningkeys(tempDir)
		So(err, ShouldNotBeNil)
	})

	Convey("signingkeys.json not exists so it is created successfully", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		_, err = extt.LoadNotationSigningkeys(tempDir)
		So(err, ShouldBeNil)
	})

	Convey("signingkeys.json not exists - error trying to create it", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		// create notation directory without write permissions
		err := os.Mkdir(dir, 0o555)
		So(err, ShouldBeNil)

		_, err = extt.LoadNotationSigningkeys(tempDir)
		So(err, ShouldNotBeNil)
	})
}

func TestLoadNotationConfig(t *testing.T) {
	Convey("directory doesn't exist", t, func() {
		_, err := extt.LoadNotationConfig(t.TempDir())
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

		_, err = extt.LoadNotationConfig(tempDir)
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

		configInfo, err := extt.LoadNotationConfig(tempDir)
		So(err, ShouldBeNil)
		So(configInfo.SignatureFormat, ShouldEqual, "jws")
	})
}

func TestSignWithNotation(t *testing.T) {
	Convey("notation directory doesn't exist", t, func() {
		err := extt.SignWithNotation("key", "reference", t.TempDir())
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

		err = extt.SignWithNotation("key", "reference", tempDir)
		So(err, ShouldEqual, extt.ErrKeyNotFound)
	})

	Convey("not enough permissions to access notation/localkeys dir", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		extt.NotationPathLock.Lock()
		defer extt.NotationPathLock.Unlock()

		extt.LoadNotationPath(tdir)

		err = extt.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = os.Chmod(path.Join(tdir, "notation", "localkeys"), 0o000)
		So(err, ShouldBeNil)

		err = extt.SignWithNotation("key", "reference", tdir)
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

		extt.NotationPathLock.Lock()
		defer extt.NotationPathLock.Unlock()

		extt.LoadNotationPath(tdir)

		err = extt.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = extt.SignWithNotation("key", "invalidReference", tdir)
		So(err, ShouldNotBeNil)
	})

	Convey("error signing", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		extt.NotationPathLock.Lock()
		defer extt.NotationPathLock.Unlock()

		extt.LoadNotationPath(tdir)

		err = extt.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = extt.SignWithNotation("key", "localhost:8080/invalidreference:1.0", tdir)
		So(err, ShouldNotBeNil)
	})
}

func TestVerifyWithNotation(t *testing.T) {
	Convey("notation directory doesn't exist", t, func() {
		err := extt.VerifyWithNotation("reference", t.TempDir())
		So(err, ShouldNotBeNil)
	})

	Convey("error parsing reference", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		extt.NotationPathLock.Lock()
		defer extt.NotationPathLock.Unlock()

		extt.LoadNotationPath(tdir)

		err = extt.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = extt.VerifyWithNotation("invalidReference", tdir)
		So(err, ShouldNotBeNil)
	})

	Convey("error trying to get manifest", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		extt.NotationPathLock.Lock()
		defer extt.NotationPathLock.Unlock()

		extt.LoadNotationPath(tdir)

		err = extt.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = extt.VerifyWithNotation("localhost:8080/invalidreference:1.0", tdir)
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

		img := test.CreateRandomImage()

		err := test.UploadImage(img, baseURL, repoName, tag)
		So(err, ShouldBeNil)

		content, err := json.Marshal(img.Manifest)
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

		extt.NotationPathLock.Lock()
		defer extt.NotationPathLock.Unlock()

		extt.LoadNotationPath(tempDir)

		err = extt.VerifyWithNotation(fmt.Sprintf("localhost:%s/%s:%s", port, repoName, tag), tempDir)
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

		_, err = extt.ListNotarySignatures("invalidReference", tdir)
		So(err, ShouldNotBeNil)
	})

	Convey("error trying to get manifest", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		_, err = extt.ListNotarySignatures("localhost:8080/invalidreference:1.0", tdir)
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

		extt.NotationPathLock.Lock()
		defer extt.NotationPathLock.Unlock()

		extt.LoadNotationPath(tempDir)

		err = extt.GenerateNotationCerts(t.TempDir(), "cert")
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

		extt.NotationPathLock.Lock()
		defer extt.NotationPathLock.Unlock()

		extt.LoadNotationPath(tempDir)

		err = extt.GenerateNotationCerts(t.TempDir(), "cert")
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

		extt.NotationPathLock.Lock()
		defer extt.NotationPathLock.Unlock()

		extt.LoadNotationPath(tempDir)

		err = extt.GenerateNotationCerts(t.TempDir(), "cert")
		So(err, ShouldNotBeNil)

		err = os.Remove(filePath)
		So(err, ShouldBeNil)
		err = os.RemoveAll(path.Join(notationDir, "localkeys"))
		So(err, ShouldBeNil)
		signingKeysBuf, err := json.Marshal(notconfig.SigningKeys{})
		So(err, ShouldBeNil)
		err = os.WriteFile(filePath, signingKeysBuf, 0o555) //nolint:gosec // test code
		So(err, ShouldBeNil)
		err = extt.GenerateNotationCerts(t.TempDir(), "cert")
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

		extt.NotationPathLock.Lock()
		defer extt.NotationPathLock.Unlock()

		extt.LoadNotationPath(tempDir)

		err = extt.GenerateNotationCerts(t.TempDir(), certName)
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

		extt.NotationPathLock.Lock()
		defer extt.NotationPathLock.Unlock()

		extt.LoadNotationPath(tempDir)

		err = extt.GenerateNotationCerts(tempDir, certName)
		So(err, ShouldNotBeNil)

		err = os.RemoveAll(path.Join(notationDir, "localkeys"))
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(notationDir, "truststore/x509"), 0o755)
		So(err, ShouldBeNil)
		_, err = os.Create(path.Join(trustStorePath, "cert-test.crt"))
		So(err, ShouldBeNil)

		err = extt.GenerateNotationCerts(tempDir, certName)
		So(err, ShouldNotBeNil)

		err = os.RemoveAll(path.Join(notationDir, "localkeys"))
		So(err, ShouldBeNil)
		err = os.Remove(path.Join(trustStorePath, "cert-test.crt"))
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(notationDir, "truststore/x509/ca", certName), 0o555)
		So(err, ShouldBeNil)

		err = extt.GenerateNotationCerts(tempDir, certName)
		So(err, ShouldNotBeNil)
	})
}
