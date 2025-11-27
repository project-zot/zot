//go:build search

package client_test

import (
	"bytes"
	"log"
	"os"
	"regexp"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/cli/client"
)

func TestConfigCmdBasics(t *testing.T) {
	Convey("Test config help", t, func() {
		args := []string{"--help"}

		_ = makeConfigFile(t, "showspinner = false")

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()

		So(err, ShouldBeNil)
		So(buff.String(), ShouldContainSubstring, "Usage")

		Convey("with the shorthand", func() {
			args[0] = "-h"

			_ = makeConfigFile(t, "showspinner = false")

			cmd := client.NewConfigCommand()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()

			So(buff.String(), ShouldContainSubstring, "Usage")
			So(err, ShouldBeNil)
		})
	})

	Convey("Test config no args", t, func() {
		args := []string{}

		_ = makeConfigFile(t, "showspinner = false")

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()

		So(buff.String(), ShouldContainSubstring, "Usage")
		So(err, ShouldNotBeNil)
	})
}

func TestConfigCmdMain(t *testing.T) {
	Convey("Test add config", t, func() {
		args := []string{"add", "configtest1", "https://test-url.com"}

		configPath := makeConfigFile(t, "")

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		_ = cmd.Execute()

		actual, err := os.ReadFile(configPath)
		if err != nil {
			panic(err)
		}
		actualStr := string(actual)
		So(actualStr, ShouldContainSubstring, "configtest1")
		So(actualStr, ShouldContainSubstring, "https://test-url.com")
	})

	Convey("Test error on home directory", t, func() {
		args := []string{"add", "configtest1", "https://test-url.com"}

		_ = makeConfigFile(t, "")

		err := os.Setenv("HOME", "nonExistentDirectory")
		if err != nil {
			panic(err)
		}

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)

		home, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}

		err = os.Setenv("HOME", home)
		if err != nil {
			log.Fatal(err)
		}
	})

	Convey("Test error on home directory at new add config", t, func() {
		args := []string{"add", "configtest1", "https://test-url.com"}

		_ = makeConfigFile(t, "")

		err := os.Setenv("HOME", "nonExistentDirectory")
		if err != nil {
			panic(err)
		}

		cmd := client.NewConfigAddCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)

		home, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}

		err = os.Setenv("HOME", home)
		if err != nil {
			log.Fatal(err)
		}
	})

	Convey("Test add config with invalid format", t, func() {
		args := []string{"--list"}

		_ = makeConfigFile(t, `{"configs":{"_name":"configtest","url":"https://test-url.com","showspinner":false}}`)

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldEqual, zerr.ErrCliBadConfig)
	})

	Convey("Test add config with invalid URL", t, func() {
		args := []string{"add", "configtest1", "test..com"}

		_ = makeConfigFile(t, "")

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(strings.Contains(err.Error(), zerr.ErrInvalidURL.Error()), ShouldBeTrue)
	})

	Convey("Test remove config entry successfully", t, func() {
		args := []string{"remove", "configtest"}

		configPath := makeConfigFile(t,
			`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldBeNil)
		actual, err := os.ReadFile(configPath)
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		actualString := space.ReplaceAllString(string(actual), " ")
		So(actualString, ShouldEqual, `{ "configs": [] }`)
	})

	Convey("Test remove missing config entry", t, func() {
		args := []string{"remove", "configtest"}

		_ = makeConfigFile(t, `{"configs":[]`)

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "does not exist")
	})

	Convey("Test remove bad config file content", t, func() {
		args := []string{"remove", "configtest"}

		_ = makeConfigFile(t, `{"asdf":[]`)

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "config json is empty")
	})

	Convey("Test remove bad config file entry", t, func() {
		args := []string{"remove", "configtest"}

		_ = makeConfigFile(t, `{"configs":[asdad]`)

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "invalid server config")
	})

	Convey("Test remove config bad permissions", t, func() {
		args := []string{"remove", "configtest"}
		configPath := makeConfigFile(t,
			`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

		defer func() {
			_ = os.Chmod(configPath, 0o600)
		}()

		err := os.Chmod(configPath, 0o400) // Read-only, so we fail only on updating the file, not reading
		So(err, ShouldBeNil)

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "permission denied")
	})

	Convey("Test fetch all config", t, func() {
		args := []string{"--list"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()

		So(buff.String(), ShouldContainSubstring, "https://test-url.com")
		So(err, ShouldBeNil)

		Convey("with the shorthand", func() {
			args := []string{"-l"}

			_ = makeConfigFile(t, `{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

			cmd := client.NewConfigCommand()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)

			err := cmd.Execute()
			So(err, ShouldBeNil)

			So(buff.String(), ShouldContainSubstring, "https://test-url.com")
		})

		Convey("From empty file", func() {
			args := []string{"-l"}

			_ = makeConfigFile(t, ``)

			cmd := client.NewConfigCommand()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)

			err := cmd.Execute()
			So(err, ShouldBeNil)

			So(strings.TrimSpace(buff.String()), ShouldEqual, "")
		})
	})

	Convey("Test fetch a config", t, func() {
		args := []string{"configtest", "--list"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)

		err := cmd.Execute()
		So(err, ShouldBeNil)

		So(buff.String(), ShouldContainSubstring, "url = https://test-url.com")
		So(buff.String(), ShouldContainSubstring, "showspinner = false")

		Convey("with the shorthand", func() {
			args := []string{"configtest", "-l"}

			_ = makeConfigFile(t, `{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

			cmd := client.NewConfigCommand()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)

			err := cmd.Execute()
			So(err, ShouldBeNil)

			So(buff.String(), ShouldContainSubstring, "url = https://test-url.com")
			So(buff.String(), ShouldContainSubstring, "showspinner = false")
		})

		Convey("From empty file", func() {
			args := []string{"configtest", "-l"}

			_ = makeConfigFile(t, ``)

			cmd := client.NewConfigCommand()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)

			err := cmd.Execute()
			So(err, ShouldBeNil)

			So(strings.TrimSpace(buff.String()), ShouldEqual, "")
		})
	})

	Convey("Test fetch a config val", t, func() {
		args := []string{"configtest", "url"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)

		err := cmd.Execute()
		So(err, ShouldBeNil)
		So(buff.String(), ShouldEqual, "https://test-url.com\n")

		Convey("From empty file", func() {
			args := []string{"configtest", "url"}

			_ = makeConfigFile(t, ``)

			cmd := client.NewConfigCommand()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)

			err := cmd.Execute()
			So(err, ShouldNotBeNil)

			So(buff.String(), ShouldContainSubstring, "does not exist")
		})
	})

	Convey("Test add a config val", t, func() {
		args := []string{"configtest", "showspinner", "false"}

		configPath := makeConfigFile(t, `{"configs":[{"_name":"configtest","url":"https://test-url.com"}]}`)

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldBeNil)

		actual, err := os.ReadFile(configPath)
		if err != nil {
			panic(err)
		}
		actualStr := string(actual)
		So(actualStr, ShouldContainSubstring, "https://test-url.com")
		So(actualStr, ShouldContainSubstring, `"showspinner": false`)
		So(buff.String(), ShouldEqual, "")

		Convey("To an empty file", func() {
			args := []string{"configtest", "showspinner", "false"}

			_ = makeConfigFile(t, ``)

			cmd := client.NewConfigCommand()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)

			err := cmd.Execute()
			So(err, ShouldNotBeNil)

			So(buff.String(), ShouldContainSubstring, "does not exist")
		})
	})

	Convey("Test overwrite a config", t, func() {
		args := []string{"configtest", "url", "https://new-url.com"}

		configPath := makeConfigFile(t,
			`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldBeNil)

		actual, err := os.ReadFile(configPath)
		if err != nil {
			panic(err)
		}
		actualStr := string(actual)
		So(actualStr, ShouldContainSubstring, `https://new-url.com`)
		So(actualStr, ShouldContainSubstring, `"showspinner": false`)
		So(actualStr, ShouldNotContainSubstring, `https://test-url.com`)
		So(buff.String(), ShouldEqual, "")
	})

	Convey("Test reset a config val", t, func() {
		args := []string{"configtest", "showspinner", "--reset"}

		configPath := makeConfigFile(t,
			`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldBeNil)

		actual, err := os.ReadFile(configPath)
		if err != nil {
			panic(err)
		}
		actualStr := string(actual)
		So(actualStr, ShouldNotContainSubstring, "showspinner")
		So(actualStr, ShouldContainSubstring, `"url": "https://test-url.com"`)
		So(buff.String(), ShouldEqual, "")
	})

	Convey("Test reset a url", t, func() {
		args := []string{"configtest", "url", "--reset"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)

		err := cmd.Execute()
		So(err, ShouldNotBeNil)

		So(buff.String(), ShouldContainSubstring, "cannot reset")
	})

	Convey("Test add a config with an existing saved name", t, func() {
		args := []string{"add", "configtest", "https://test-url.com/new"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)

		err := cmd.Execute()
		So(err, ShouldNotBeNil)

		So(buff.String(), ShouldContainSubstring, "cli config name already added")
	})
}
