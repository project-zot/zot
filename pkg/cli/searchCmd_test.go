package cli_test

import (
	"bytes"
	"testing"

	zotErrors "github.com/anuvu/zot/errors"

	"github.com/anuvu/zot/pkg/cli"
	. "github.com/smartystreets/goconvey/convey"
)

func TestSearchCmd(t *testing.T) {
	Convey("Test search help", t, func() {
		args := []string{"search", "--help"}
		cmd := cli.NewRootCmd()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "Usage")
		So(err, ShouldBeNil)
		Convey("with the shorthand", func() {
			args[1] = "-h"
			cmd := cli.NewRootCmd()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(buff.String(), ShouldContainSubstring, "Usage")
			So(err, ShouldBeNil)
		})
	})

	Convey("Test search invalid subcommand", t, func() {
		args := []string{"search", "randomSubCommand"}
		cmd := cli.NewRootCmd()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "Usage")
		So(err, ShouldBeNil)
	})

	Convey("Test search invalid flag", t, func() {
		args := []string{"search", "--random"}
		cmd := cli.NewRootCmd()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "unknown flag")
		So(err, ShouldNotBeNil)
		Convey("and a shorthand", func() {
			args[1] = "-r"
			cmd := cli.NewRootCmd()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(buff.String(), ShouldContainSubstring, "unknown shorthand flag")
			So(err, ShouldNotBeNil)
		})
	})

}

func TestSearchCveCmd(t *testing.T) {
	Convey("Test cve help", t, func() {
		args := []string{"search", "cve", "--help"}
		cmd := cli.NewRootCmd()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "Usage")
		So(err, ShouldBeNil)
		Convey("with the shorthand", func() {
			args[2] = "-h"
			cmd := cli.NewRootCmd()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(buff.String(), ShouldContainSubstring, "Usage")
			So(err, ShouldBeNil)
		})
	})

	Convey("Test cve no args", t, func() {
		args := []string{"search", "cve"}
		cmd := cli.NewRootCmd()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldEqual, zotErrors.ErrInvalidArgs)
	})
	Convey("with invalid arg combination", t, func() {
		args := []string{"search", "cve", "--cve-id", "dummyId", "--package-name", "dummyPackageName"}
		cmd := cli.NewRootCmd()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldEqual, zotErrors.ErrInvalidFlagsCombination)
	})
	Convey("Test cve by id", t, func() {
		args := []string{"search", "cve", "--cve-id", "cveid"}
		cmd := cli.NewRootCmd()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "Searching with CVE ID: cveid") //TODO change asserts after integrating API
		So(err, ShouldBeNil)
	})

}
