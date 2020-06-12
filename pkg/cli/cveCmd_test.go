package cli

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
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
		cmd.SetErr(ioutil.Discard)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "Usage")
		So(err, ShouldBeNil)
		Convey("with the shorthand", func() {
			args[0] = "-h"
			cmd := NewCveCommand(new(mockService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(ioutil.Discard)
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
		cmd.SetErr(ioutil.Discard)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test cve no params", t, func() {
		args := []string{"--url", "someUrl"}
		cmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(ioutil.Discard)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldEqual, zotErrors.ErrInvalidArgs)
	})

	Convey("Test invalid arg combination", t, func() {
		args := []string{"--cve-id", "dummyIdRandom", "--package-name", "dummyPackageName", "--url", "someUrl"}
		cmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(ioutil.Discard)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldEqual, zotErrors.ErrInvalidFlagsCombination)
	})
	Convey("Test cve invalid url", t, func() {
		args := []string{"--image-name", "dummyImageName", "--url", "invalidUrl"}
		cmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(ioutil.Discard)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldEqual, zotErrors.ErrInvalidURL)
	})
	Convey("Test cve invalid url port", t, func() {
		args := []string{"--image-name", "dummyImageName", "--url", "http://localhost:99999"}
		cmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(ioutil.Discard)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})
	Convey("Test cve invalid url port with user", t, func() {
		args := []string{"--image-name", "dummyImageName", "--url", "http://localhost:99999", "--user", "test:test"}
		cmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(ioutil.Discard)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})
	Convey("Test cve by image name", t, func() {
		args := []string{"--image-name", "dummyImageName", "--url", "someUrl"}
		cmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(ioutil.Discard)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(strings.TrimSpace(buff.String()), ShouldEqual, "")
		So(err, ShouldBeNil)
		Convey("using shorthand", func() {
			args := []string{"-I", "dummyImageNameShort", "--url", "someUrl"}
			buff := bytes.NewBufferString("")
			cmd := NewCveCommand(new(mockService))
			cmd.SetOut(buff)
			cmd.SetErr(ioutil.Discard)
			cmd.SetArgs(args)
			err := cmd.Execute()
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
		cmd.SetErr(ioutil.Discard)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "Usage")
		So(err, ShouldBeNil)
		Convey("with the shorthand", func() {
			args[0] = "-h"
			cmd := NewImageCommand(new(mockService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(ioutil.Discard)
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
		cmd.SetErr(ioutil.Discard)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test image no params", t, func() {
		args := []string{"--url", "someUrl"}
		cmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(ioutil.Discard)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldEqual, zotErrors.ErrInvalidArgs)
	})
	Convey("Test image invalid url", t, func() {
		args := []string{"--cve-id", "dummyCveId", "--url", "invalidUrl"}
		cmd := NewImageCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(ioutil.Discard)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldEqual, zotErrors.ErrInvalidURL)
	})
	Convey("Test image invalid url port", t, func() {
		args := []string{"--cve-id", "dummyCveId", "--url", "http://localhost:99999"}
		cmd := NewImageCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(ioutil.Discard)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test image with user", t, func() {
		args := []string{"--cve-id", "dummyCveId", "--url", "http://localhost:99999", "--user", "test:test"}
		cmd := NewImageCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(ioutil.Discard)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test image by cve id", t, func() {
		args := []string{"--cve-id", "dummyCveID", "--url", "someUrlImage"}
		imageCmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		imageCmd.SetOut(buff)
		imageCmd.SetErr(ioutil.Discard)
		imageCmd.SetArgs(args)
		err := imageCmd.Execute()
		So(strings.TrimSpace(buff.String()), ShouldEqual, "")
		So(err, ShouldBeNil)
		Convey("using shorthand", func() {
			args := []string{"-c", "dummyCveIDShort", "--url", "someUrlImage"}
			buff := bytes.NewBufferString("")
			imageCmd := NewImageCommand(new(mockService))
			imageCmd.SetOut(buff)
			imageCmd.SetErr(ioutil.Discard)
			imageCmd.SetArgs(args)
			err := imageCmd.Execute()

			So(strings.TrimSpace(buff.String()), ShouldEqual, "")
			So(err, ShouldBeNil)
		})
	})
}

func TestResponseStructs(t *testing.T) {
	Convey("Test ImageListForCVEStruct string", t, func() {
		jsonData := []byte(`{"data":{"ImageListForCVE":[{"Name":"dummyName","Tags":["dummyTag"]}]}}`)
		testStruct := ImageListForCVEStruct{}
		err := json.Unmarshal(jsonData, &testStruct)
		if err != nil {
			t.FailNow()
		}
		expected :=
			`Images List:
Name:dummyName
+----------+
|   TAG    |
+----------+
| dummyTag |
+----------+

`
		So(testStruct.String(), ShouldEqual, expected)
	})

	Convey("Test CVEListForImageStruct string", t, func() {
		jsonData := []byte(`{"data":{"CVEListForImage":[{"Tag":"dummyTag","CVEList":[
			{"Id":"id1","Description":"desc1","Severity":"s1"},
			{"Id":"id2","Description":"desc2","Severity":"s2"}]}]}}`)
		testStruct := CVEListForImageStruct{}
		err := json.Unmarshal(jsonData, &testStruct)
		if err != nil {
			t.FailNow()
		}
		expected :=
			`Tag:dummyTag
CVE List:
+-----+-------------+----------+
| ID  | DESCRIPTION | SEVERITY |
+-----+-------------+----------+
| id1 | s1          | desc1    |
+-----+-------------+----------+
| id2 | s2          | desc2    |
+-----+-------------+----------+

`
		So(testStruct.String(), ShouldEqual, expected)
	})
}

type mockService struct{}

func (service mockService) findCveByImageName(imageName, serverURL,
	username, password string) (CVEListForImageStruct, error) {
	return CVEListForImageStruct{}, nil
}

func (service mockService) findImagesByCveID(cveID, serverURL,
	username, password string) (ImageListForCVEStruct, error) {
	return ImageListForCVEStruct{}, nil
}
