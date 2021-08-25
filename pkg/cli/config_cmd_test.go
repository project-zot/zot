// +build extended

package cli //nolint:testpackage

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	zotErrors "github.com/anuvu/zot/errors"

	. "github.com/smartystreets/goconvey/convey"
)

func TestConfigCmdBasics(t *testing.T) {
	Convey("Test config help", t, func() {
		args := []string{"--help"}
		configPath := makeConfigFile("showspinner = false")
		defer os.Remove(configPath)
		cmd := NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "Usage")
		So(err, ShouldBeNil)
		Convey("with the shorthand", func() {
			args[0] = "-h"
			configPath := makeConfigFile("showspinner = false")
			defer os.Remove(configPath)
			cmd := NewConfigCommand()
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
		configPath := makeConfigFile("showspinner = false")
		defer os.Remove(configPath)
		cmd := NewConfigCommand()
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
		file := makeConfigFile("")
		defer os.Remove(file)
		cmd := NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		_ = cmd.Execute()

		actual, err := ioutil.ReadFile(file)
		if err != nil {
			panic(err)
		}
		actualStr := string(actual)
		So(actualStr, ShouldContainSubstring, "configtest1")
		So(actualStr, ShouldContainSubstring, "https://test-url.com")
	})

	Convey("Test add config with invalid URL", t, func() {
		args := []string{"add", "configtest1", "test..com"}
		file := makeConfigFile("")
		defer os.Remove(file)
		cmd := NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zotErrors.ErrInvalidURL)
	})

	Convey("Test fetch all config", t, func() {
		args := []string{"--list"}
		configPath := makeConfigFile(`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "https://test-url.com")
		So(err, ShouldBeNil)

		Convey("with the shorthand", func() {
			args := []string{"-l"}
			configPath := makeConfigFile(`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)
			defer os.Remove(configPath)
			cmd := NewConfigCommand()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(buff.String(), ShouldContainSubstring, "https://test-url.com")
			So(err, ShouldBeNil)
		})

		Convey("From empty file", func() {
			args := []string{"-l"}
			configPath := makeConfigFile(``)
			defer os.Remove(configPath)
			cmd := NewConfigCommand()
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
		configPath := makeConfigFile(`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "url = https://test-url.com")
		So(buff.String(), ShouldContainSubstring, "showspinner = false")
		So(err, ShouldBeNil)

		Convey("with the shorthand", func() {
			args := []string{"configtest", "-l"}
			configPath := makeConfigFile(`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)
			defer os.Remove(configPath)
			cmd := NewConfigCommand()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(buff.String(), ShouldContainSubstring, "url = https://test-url.com")
			So(buff.String(), ShouldContainSubstring, "showspinner = false")
			So(err, ShouldBeNil)
		})

		Convey("From empty file", func() {
			args := []string{"configtest", "-l"}
			configPath := makeConfigFile(``)
			defer os.Remove(configPath)
			cmd := NewConfigCommand()
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
		configPath := makeConfigFile(`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldEqual, "https://test-url.com\n")
		So(err, ShouldBeNil)

		Convey("From empty file", func() {
			args := []string{"configtest", "url"}
			configPath := makeConfigFile(``)
			defer os.Remove(configPath)
			cmd := NewConfigCommand()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
			fmt.Println(err)
			fmt.Println(buff.String())
			So(buff.String(), ShouldContainSubstring, "does not exist")
		})
	})

	Convey("Test add a config val", t, func() {
		args := []string{"configtest", "showspinner", "false"}
		configPath := makeConfigFile(`{"configs":[{"_name":"configtest","url":"https://test-url.com"}]}`)
		defer os.Remove(configPath)
		cmd := NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldBeNil)

		actual, err := ioutil.ReadFile(configPath)
		if err != nil {
			panic(err)
		}
		actualStr := string(actual)
		So(actualStr, ShouldContainSubstring, "https://test-url.com")
		So(actualStr, ShouldContainSubstring, `"showspinner":false`)
		So(buff.String(), ShouldEqual, "")

		Convey("To an empty file", func() {
			args := []string{"configtest", "showspinner", "false"}
			configPath := makeConfigFile(``)
			defer os.Remove(configPath)
			cmd := NewConfigCommand()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
			fmt.Println(err)
			fmt.Println(buff.String())
			So(buff.String(), ShouldContainSubstring, "does not exist")
		})
	})

	Convey("Test overwrite a config", t, func() {
		args := []string{"configtest", "url", "https://new-url.com"}
		configPath := makeConfigFile(`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldBeNil)

		actual, err := ioutil.ReadFile(configPath)
		if err != nil {
			panic(err)
		}
		actualStr := string(actual)
		So(actualStr, ShouldContainSubstring, `https://new-url.com`)
		So(actualStr, ShouldContainSubstring, `"showspinner":false`)
		So(actualStr, ShouldNotContainSubstring, `https://test-url.com`)
		So(buff.String(), ShouldEqual, "")
	})

	Convey("Test reset a config val", t, func() {
		args := []string{"configtest", "showspinner", "--reset"}
		configPath := makeConfigFile(`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldBeNil)

		actual, err := ioutil.ReadFile(configPath)
		if err != nil {
			panic(err)
		}
		actualStr := string(actual)
		So(actualStr, ShouldNotContainSubstring, "showspinner")
		So(actualStr, ShouldContainSubstring, `"url":"https://test-url.com"`)
		So(buff.String(), ShouldEqual, "")
	})

	Convey("Test reset a url", t, func() {
		args := []string{"configtest", "url", "--reset"}
		configPath := makeConfigFile(`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewConfigCommand()
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
		configPath := makeConfigFile(`{"configs":[{"_name":"configtest","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewConfigCommand()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "cli config name already added")
	})
}
