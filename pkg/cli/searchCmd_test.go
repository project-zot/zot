package cli

import (
	"bytes"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSearchCmd(t *testing.T) {
	Convey("Test search help", t, func() {
		args := []string{"--help"}
		cmd := NewSearchCmd()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "Usage")
		So(err, ShouldBeNil)
		Convey("with the shorthand", func() {
			args[0] = "-h"
			cmd := NewSearchCmd()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(buff.String(), ShouldContainSubstring, "Usage")
			So(err, ShouldBeNil)
		})
	})

	Convey("Test search invalid subcommand", t, func() {
		args := []string{"randomSubCommand"}
		cmd := NewSearchCmd()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "usage")
		So(err, ShouldNotBeNil)
	})

	Convey("Test search invalid flag", t, func() {
		args := []string{"--random"}
		cmd := NewSearchCmd()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "unknown flag")
		So(err, ShouldNotBeNil)
		Convey("and a shorthand", func() {
			args[0] = "-r"
			cmd := NewSearchCmd()
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(buff.String(), ShouldContainSubstring, "unknown shorthand flag")
			So(err, ShouldNotBeNil)
		})
	})

}
