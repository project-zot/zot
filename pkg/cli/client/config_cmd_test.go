//go:build search

package client_test

import (
	"bytes"
	"errors"
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
		So(err, ShouldBeNil)
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

	Convey("Test add config rejects reserved names", t, func() {
		args := []string{"add", "list", "https://test-url.com"}

		_ = makeConfigFile(t, "")

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()

		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrReservedConfigName), ShouldBeTrue)
		So(err.Error(), ShouldContainSubstring, `"list"`)
	})

	Convey("Test reserved-named profiles are still accessible for migration", t, func() {
		_ = makeConfigFile(t,
			`{"configs":[{"_name":"list","url":"https://test-url.com","showspinner":false}]}`)

		Convey("show", func() {
			cmd := client.NewConfigCommand()
			out := bytes.NewBufferString("")
			errOut := bytes.NewBufferString("")
			cmd.SetOut(out)
			cmd.SetErr(errOut)
			cmd.SetArgs([]string{"show", "list"})
			err := cmd.Execute()
			So(err, ShouldBeNil)
			So(out.String(), ShouldContainSubstring, "https://test-url.com")
		})

		Convey("get", func() {
			cmd := client.NewConfigCommand()
			out := bytes.NewBufferString("")
			errOut := bytes.NewBufferString("")
			cmd.SetOut(out)
			cmd.SetErr(errOut)
			cmd.SetArgs([]string{"get", "list", "url"})
			err := cmd.Execute()
			So(err, ShouldBeNil)
			So(out.String(), ShouldContainSubstring, "https://test-url.com")
		})

		Convey("remove", func() {
			cmd := client.NewConfigCommand()
			out := bytes.NewBufferString("")
			errOut := bytes.NewBufferString("")
			cmd.SetOut(out)
			cmd.SetErr(errOut)
			cmd.SetArgs([]string{"remove", "list"})
			err := cmd.Execute()
			So(err, ShouldBeNil)
		})
	})

	Convey("Test error on home directory", t, func() {
		args := []string{"add", "configtest1", "https://test-url.com"}

		_ = makeConfigFile(t, "")

		t.Setenv("HOME", "nonExistentDirectory")

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test error on home directory at new add config", t, func() {
		args := []string{"configtest1", "https://test-url.com"}

		_ = makeConfigFile(t, "")

		t.Setenv("HOME", "nonExistentDirectory")

		cmd := client.NewConfigAddCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test list config with invalid format", t, func() {
		args := []string{"list"}

		_ = makeConfigFile(t, `{"configs":{"_name":"configtest","url":"https://test-url.com","showspinner":false}}`)

		cmd := client.NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(errors.Is(err, zerr.ErrCliBadConfig), ShouldBeTrue)
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

		_ = makeConfigFile(t, `{"configs":[]}`)

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
		So(errors.Is(err, zerr.ErrCliBadConfig), ShouldBeTrue)
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
		So(buff.String(), ShouldContainSubstring, zerr.ErrCliBadConfig.Error())
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

	Convey("Test config list", t, func() {
		Convey("prints profile names and URLs", func() {
			_ = makeConfigFile(t, `{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

			cmd := client.NewConfigCommand()
			outBuff := bytes.NewBufferString("")
			errBuff := bytes.NewBufferString("")
			cmd.SetOut(outBuff)
			cmd.SetErr(errBuff)
			cmd.SetArgs([]string{"list"})
			So(cmd.Execute(), ShouldBeNil)
			So(outBuff.String(), ShouldContainSubstring, "https://test-url.com")
			So(errBuff.String(), ShouldEqual, "")
		})

		Convey("from empty config file", func() {
			_ = makeConfigFile(t, ``)

			cmd := client.NewConfigCommand()
			outBuff := bytes.NewBufferString("")
			errBuff := bytes.NewBufferString("")
			cmd.SetOut(outBuff)
			cmd.SetErr(errBuff)
			cmd.SetArgs([]string{"list"})
			So(cmd.Execute(), ShouldBeNil)
			So(strings.TrimSpace(outBuff.String()), ShouldEqual, "")
			So(errBuff.String(), ShouldEqual, "")
		})

		Convey("rejects stale defaultConfigName", func() {
			_ = makeConfigFile(t,
				`{"configs":[{"_name":"configtest","url":"https://test-url.com"}],"defaultConfigName":"missing"}`)

			cmd := client.NewConfigCommand()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs([]string{"list"})
			err := cmd.Execute()

			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrConfigNotFound), ShouldBeTrue)
			So(buff.String(), ShouldContainSubstring, "defaultConfigName")
		})
	})

	Convey("Test config default profile commands", t, func() {
		Convey("sets and displays the default profile", func() {
			configPath := makeConfigFile(t,
				`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

			cmd := client.NewConfigCommand()
			outBuff := bytes.NewBufferString("")
			errBuff := bytes.NewBufferString("")
			cmd.SetOut(outBuff)
			cmd.SetErr(errBuff)
			cmd.SetArgs([]string{"set-default", "configtest"})
			So(cmd.Execute(), ShouldBeNil)

			actual, err := os.ReadFile(configPath)
			So(err, ShouldBeNil)
			So(string(actual), ShouldContainSubstring, `"defaultConfigName": "configtest"`)

			listCmd := client.NewConfigCommand()
			listOut := bytes.NewBufferString("")
			listErr := bytes.NewBufferString("")
			listCmd.SetOut(listOut)
			listCmd.SetErr(listErr)
			listCmd.SetArgs([]string{"list"})
			So(listCmd.Execute(), ShouldBeNil)
			So(listOut.String(), ShouldContainSubstring, "configtest (default)")
			So(listErr.String(), ShouldEqual, "")

			showCmd := client.NewConfigCommand()
			showOut := bytes.NewBufferString("")
			showErr := bytes.NewBufferString("")
			showCmd.SetOut(showOut)
			showCmd.SetErr(showErr)
			showCmd.SetArgs([]string{"show", "configtest"})
			So(showCmd.Execute(), ShouldBeNil)
			So(showOut.String(), ShouldContainSubstring, "default = true")
			So(showErr.String(), ShouldEqual, "")
		})

		Convey("rejects a missing default profile", func() {
			_ = makeConfigFile(t,
				`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

			cmd := client.NewConfigCommand()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs([]string{"set-default", "missing"})
			err := cmd.Execute()

			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrConfigNotFound), ShouldBeTrue)
		})

		Convey("set-default errors when home directory is unavailable", func() {
			t.Setenv("HOME", "nonExistentDirectory")

			cmd := client.NewConfigCommand()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs([]string{"set-default", "configtest"})
			err := cmd.Execute()

			So(err, ShouldNotBeNil)
		})

		Convey("clears the default profile", func() {
			configPath := makeConfigFile(t,
				`{"configs":[{"_name":"configtest","url":"https://test-url.com",`+
					`"showspinner":false}],"defaultConfigName":"configtest"}`)

			cmd := client.NewConfigCommand()
			outBuff := bytes.NewBufferString("")
			errBuff := bytes.NewBufferString("")
			cmd.SetOut(outBuff)
			cmd.SetErr(errBuff)
			cmd.SetArgs([]string{"clear-default"})
			So(cmd.Execute(), ShouldBeNil)
			So(outBuff.String(), ShouldEqual, "")
			So(errBuff.String(), ShouldEqual, "")

			actual, err := os.ReadFile(configPath)
			So(err, ShouldBeNil)
			So(string(actual), ShouldNotContainSubstring, "defaultConfigName")
		})

		Convey("remove clears the default profile", func() {
			configPath := makeConfigFile(t,
				`{"configs":[{"_name":"configtest","url":"https://test-url.com",`+
					`"showspinner":false}],"defaultConfigName":"configtest"}`)

			cmd := client.NewConfigCommand()
			outBuff := bytes.NewBufferString("")
			errBuff := bytes.NewBufferString("")
			cmd.SetOut(outBuff)
			cmd.SetErr(errBuff)
			cmd.SetArgs([]string{"remove", "configtest"})
			So(cmd.Execute(), ShouldBeNil)

			actual, err := os.ReadFile(configPath)
			So(err, ShouldBeNil)
			So(string(actual), ShouldNotContainSubstring, "defaultConfigName")
		})

		Convey("clear-default errors when home directory is unavailable", func() {
			t.Setenv("HOME", "nonExistentDirectory")

			cmd := client.NewConfigCommand()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs([]string{"clear-default"})
			err := cmd.Execute()

			So(err, ShouldNotBeNil)
		})
	})

	Convey("Test config show", t, func() {
		Convey("prints variables for the profile", func() {
			_ = makeConfigFile(t, `{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

			cmd := client.NewConfigCommand()
			outBuff := bytes.NewBufferString("")
			errBuff := bytes.NewBufferString("")
			cmd.SetOut(outBuff)
			cmd.SetErr(errBuff)
			cmd.SetArgs([]string{"show", "configtest"})
			So(cmd.Execute(), ShouldBeNil)
			So(outBuff.String(), ShouldContainSubstring, "url = https://test-url.com")
			So(outBuff.String(), ShouldContainSubstring, "showspinner = false")
			So(errBuff.String(), ShouldEqual, "")
		})

		Convey("rejects stale defaultConfigName", func() {
			_ = makeConfigFile(t,
				`{"configs":[{"_name":"configtest","url":"https://test-url.com"}],"defaultConfigName":"missing"}`)

			cmd := client.NewConfigCommand()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs([]string{"show", "configtest"})
			err := cmd.Execute()

			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrConfigNotFound), ShouldBeTrue)
			So(buff.String(), ShouldContainSubstring, "defaultConfigName")
		})

		Convey("from empty config file", func() {
			_ = makeConfigFile(t, ``)

			cmd := client.NewConfigCommand()
			outBuff := bytes.NewBufferString("")
			errBuff := bytes.NewBufferString("")
			cmd.SetOut(outBuff)
			cmd.SetErr(errBuff)
			cmd.SetArgs([]string{"show", "configtest"})
			So(cmd.Execute(), ShouldBeNil)
			So(strings.TrimSpace(outBuff.String()), ShouldEqual, "")
			So(errBuff.String(), ShouldEqual, "")
		})
	})

	Convey("Test config get", t, func() {
		Convey("prints one key", func() {
			_ = makeConfigFile(t, `{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

			cmd := client.NewConfigCommand()
			outBuff := bytes.NewBufferString("")
			errBuff := bytes.NewBufferString("")
			cmd.SetOut(outBuff)
			cmd.SetErr(errBuff)
			cmd.SetArgs([]string{"get", "configtest", "url"})
			So(cmd.Execute(), ShouldBeNil)
			So(outBuff.String(), ShouldEqual, "https://test-url.com\n")
			So(errBuff.String(), ShouldEqual, "")
		})

		Convey("from empty config file", func() {
			_ = makeConfigFile(t, ``)

			cmd := client.NewConfigCommand()
			outBuff := bytes.NewBufferString("")
			errBuff := bytes.NewBufferString("")
			cmd.SetOut(outBuff)
			cmd.SetErr(errBuff)
			cmd.SetArgs([]string{"get", "configtest", "url"})
			So(cmd.Execute(), ShouldNotBeNil)

			combined := errBuff.String() + outBuff.String()
			So(combined, ShouldContainSubstring, "does not exist")
		})
	})

	Convey("Test config set", t, func() {
		Convey("adds a variable", func() {
			configPath := makeConfigFile(t, `{"configs":[{"_name":"configtest","url":"https://test-url.com"}]}`)

			cmd := client.NewConfigCommand()
			outBuff := bytes.NewBufferString("")
			errBuff := bytes.NewBufferString("")
			cmd.SetOut(outBuff)
			cmd.SetErr(errBuff)
			cmd.SetArgs([]string{"set", "configtest", "showspinner", "false"})
			So(cmd.Execute(), ShouldBeNil)
			So(outBuff.String(), ShouldEqual, "")
			So(errBuff.String(), ShouldEqual, "")

			actual, err := os.ReadFile(configPath)
			So(err, ShouldBeNil)
			actualStr := string(actual)
			So(actualStr, ShouldContainSubstring, "https://test-url.com")
			So(actualStr, ShouldContainSubstring, `"showspinner": false`)
		})

		Convey("to an empty config file", func() {
			_ = makeConfigFile(t, ``)

			cmd := client.NewConfigCommand()
			outBuff := bytes.NewBufferString("")
			errBuff := bytes.NewBufferString("")
			cmd.SetOut(outBuff)
			cmd.SetErr(errBuff)
			cmd.SetArgs([]string{"set", "configtest", "showspinner", "false"})
			So(cmd.Execute(), ShouldNotBeNil)

			combined := errBuff.String() + outBuff.String()
			So(combined, ShouldContainSubstring, "does not exist")
		})
	})

	Convey("Test config set overwrites URL", t, func() {
		configPath := makeConfigFile(t,
			`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

		cmd := client.NewConfigCommand()
		outBuff := bytes.NewBufferString("")
		errBuff := bytes.NewBufferString("")
		cmd.SetOut(outBuff)
		cmd.SetErr(errBuff)
		cmd.SetArgs([]string{"set", "configtest", "url", "https://new-url.com"})
		So(cmd.Execute(), ShouldBeNil)
		So(outBuff.String(), ShouldEqual, "")
		So(errBuff.String(), ShouldEqual, "")

		actual, err := os.ReadFile(configPath)
		So(err, ShouldBeNil)
		actualStr := string(actual)
		So(actualStr, ShouldContainSubstring, `https://new-url.com`)
		So(actualStr, ShouldContainSubstring, `"showspinner": false`)
		So(actualStr, ShouldNotContainSubstring, `https://test-url.com`)
	})

	Convey("Test config reset", t, func() {
		Convey("clears an optional variable", func() {
			configPath := makeConfigFile(t,
				`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

			cmd := client.NewConfigCommand()
			outBuff := bytes.NewBufferString("")
			errBuff := bytes.NewBufferString("")
			cmd.SetOut(outBuff)
			cmd.SetErr(errBuff)
			cmd.SetArgs([]string{"reset", "configtest", "showspinner"})
			So(cmd.Execute(), ShouldBeNil)
			So(outBuff.String(), ShouldEqual, "")
			So(errBuff.String(), ShouldEqual, "")

			actual, err := os.ReadFile(configPath)
			So(err, ShouldBeNil)
			actualStr := string(actual)
			So(actualStr, ShouldNotContainSubstring, "showspinner")
			So(actualStr, ShouldContainSubstring, `"url": "https://test-url.com"`)
		})

		Convey("rejects resetting url", func() {
			_ = makeConfigFile(t, `{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)

			cmd := client.NewConfigCommand()
			outBuff := bytes.NewBufferString("")
			errBuff := bytes.NewBufferString("")
			cmd.SetOut(outBuff)
			cmd.SetErr(errBuff)
			cmd.SetArgs([]string{"reset", "configtest", "url"})

			So(cmd.Execute(), ShouldNotBeNil)

			combined := errBuff.String() + outBuff.String()
			So(combined, ShouldContainSubstring, "cannot reset")
		})
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
