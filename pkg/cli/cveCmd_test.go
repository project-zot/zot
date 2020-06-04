package cli

import (
	"bytes"
	"strings"
	"testing"

	zotErrors "github.com/anuvu/zot/errors"
	. "github.com/smartystreets/goconvey/convey"
)

func TestSearchCveCmd(t *testing.T) {
	Convey("Test cve help", t, func() {
		args := []string{"--help"}
		cmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "Usage")
		So(err, ShouldBeNil)
		Convey("with the shorthand", func() {
			args[0] = "-h"
			cmd := NewCveCommand(new(mockService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(buff.String(), ShouldContainSubstring, "Usage")
			So(err, ShouldBeNil)
		})
	})
	Convey("Test cve no url", t, func() {
		args := []string{"--cve-id", "dummyIdRandom"}
		cmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test cve no params", t, func() {
		args := []string{"--url", "someUrl"}
		cmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldEqual, zotErrors.ErrInvalidArgs)
	})

	Convey("Test invalid arg combination", t, func() {
		args := []string{"--cve-id", "dummyIdRandom", "--package-name", "dummyPackageName", "--url", "someUrl"}
		cmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldEqual, zotErrors.ErrInvalidFlagsCombination)
	})
	Convey("Test cve invalid url", t, func() {
		args := []string{"--image-name", "dummyImageName", "--url", "invalidUrl"}
		cmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldEqual, zotErrors.ErrInvalidURL)
	})
	Convey("Test cve invalid url port", t, func() {
		args := []string{"--image-name", "dummyImageName", "--url", "https://localhost:99999"}
		cmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})
	Convey("Test cve by image name", t, func() {
		args := []string{"--image-name", "dummyImageName", "--url", "someUrl"}
		cmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(inputTestImageName, ShouldEqual, "dummyImageName")
		So(urlTest, ShouldEqual, "someUrl")
		So(strings.TrimSpace(buff.String()), ShouldEqual, "")
		So(err, ShouldBeNil)
		Convey("using shorthand", func() {
			args := []string{"-I", "dummyImageNameShort", "--url", "someUrl"}
			buff := bytes.NewBufferString("")
			cmd := NewCveCommand(new(mockService))
			cmd.SetOut(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(inputTestImageName, ShouldEqual, "dummyImageNameShort")
			So(urlTest, ShouldEqual, "someUrl")
			So(strings.TrimSpace(buff.String()), ShouldEqual, "")
			So(err, ShouldBeNil)
		})
	})

}

func TestSearchImageCmd(t *testing.T) {
	Convey("Test image help", t, func() {
		args := []string{"--help"}
		cmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "Usage")
		So(err, ShouldBeNil)
		Convey("with the shorthand", func() {
			args[0] = "-h"
			cmd := NewImageCommand(new(mockService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(buff.String(), ShouldContainSubstring, "Usage")
			So(err, ShouldBeNil)
		})
	})
	Convey("Test image no url", t, func() {
		args := []string{"--cve-id", "dummyIdRandom"}
		cmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test image no params", t, func() {
		args := []string{"--url", "someUrl"}
		cmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldEqual, zotErrors.ErrInvalidArgs)
	})
	Convey("Test image invalid url", t, func() {
		args := []string{"--cve-id", "dummyCveId", "--url", "invalidUrl"}
		cmd := NewImageCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldEqual, zotErrors.ErrInvalidURL)
	})
	Convey("Test image invalid url port", t, func() {
		args := []string{"--cve-id", "dummyCveId", "--url", "https://localhost:99999"}
		cmd := NewImageCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})
	Convey("Test image by cve id", t, func() {
		args := []string{"--cve-id", "dummyCveID", "--url", "someUrlImage"}
		imageCmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		imageCmd.SetOut(buff)
		imageCmd.SetArgs(args)
		err := imageCmd.Execute()
		So(inputTestCveId, ShouldEqual, "dummyCveID")
		So(urlTest, ShouldEqual, "someUrlImage")
		So(strings.TrimSpace(buff.String()), ShouldEqual, "")
		So(err, ShouldBeNil)
		Convey("using shorthand", func() {
			args := []string{"-c", "dummyCveIDShort", "--url", "someUrlImage"}
			buff := bytes.NewBufferString("")
			imageCmd := NewImageCommand(new(mockService))
			imageCmd.SetOut(buff)
			imageCmd.SetArgs(args)
			err := imageCmd.Execute()
			So(inputTestCveId, ShouldEqual, "dummyCveIDShort")
			So(urlTest, ShouldEqual, "someUrlImage")

			So(strings.TrimSpace(buff.String()), ShouldEqual, "")
			So(err, ShouldBeNil)
		})
	})
}

type mockService struct{}

var inputTestImageName string
var inputTestCveId string
var urlTest string

func (service mockService) findCveByImageName(imageName string, serverUrl string) (CVEListForImageStruct, error) {
	inputTestImageName = imageName
	urlTest = serverUrl
	return CVEListForImageStruct{}, nil
}

func (service mockService) findImagesByCveId(cveID string, serverUrl string) (ImageListForCVEStruct, error) {
	inputTestCveId = cveID
	urlTest = serverUrl
	return ImageListForCVEStruct{}, nil
}
