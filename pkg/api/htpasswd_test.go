package api_test

import (
	"os"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/crypto/bcrypt"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api"
	test "zotregistry.dev/zot/pkg/test/common"
)

func TestHtpasswdClient_ChangePassword(t *testing.T) {
	Convey("test htpasswd client change oldPassword", t, func() {
		username, _ := test.GenerateRandomString()
		oldPassword, _ := test.GenerateRandomString()
		newPassword, _ := test.GenerateRandomString()

		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, oldPassword))
		defer os.Remove(htpasswdPath)

		client := api.NewHtpasswdClient(htpasswdPath)
		So(client.Init(), ShouldBeNil)

		Convey("change for non-existing login", func() {
			err := client.ChangePassword("non-existing", "old_password", "new_password")
			So(err, ShouldEqual, zerr.ErrBadUser)
		})

		Convey("change with wrong old oldPassword", func() {
			err := client.ChangePassword(username, "wrong_password", "new_password")
			So(err, ShouldEqual, zerr.ErrOldPasswordIsWrong)

			passphrase, ok := client.Get(username)
			So(ok, ShouldBeTrue)
			So(bcrypt.CompareHashAndPassword([]byte(passphrase), []byte(oldPassword)), ShouldBeNil)
		})

		Convey("change with empty new oldPassword", func() {
			err := client.ChangePassword(username, oldPassword, "")
			So(err, ShouldEqual, zerr.ErrPasswordIsEmpty)

			passphrase, ok := client.Get(username)
			So(ok, ShouldBeTrue)
			So(bcrypt.CompareHashAndPassword([]byte(passphrase), []byte(oldPassword)), ShouldBeNil)
		})

		Convey("change to the same password", func() {
			err := client.ChangePassword(username, oldPassword, oldPassword)
			So(err, ShouldBeNil)

			passphrase, ok := client.Get(username)
			So(ok, ShouldBeTrue)
			So(bcrypt.CompareHashAndPassword([]byte(passphrase), []byte(oldPassword)), ShouldBeNil)
		})

		Convey("change to the new password", func() {
			err := client.ChangePassword(username, oldPassword, newPassword)
			So(err, ShouldBeNil)

			passphrase, ok := client.Get(username)
			So(ok, ShouldBeTrue)
			So(bcrypt.CompareHashAndPassword([]byte(passphrase), []byte(newPassword)), ShouldBeNil)

			// check htpasswd file to ensure the new password is written
			fileContent, err := os.ReadFile(htpasswdPath)
			So(err, ShouldBeNil)
			lines := strings.Split(string(fileContent), "\n")
			found := false
			for _, line := range lines {
				if strings.HasPrefix(line, username+":") {
					found = true
					So(line, ShouldEqual, username+":"+passphrase)

					break
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestHtpasswdClient_CheckPassword(t *testing.T) {
	Convey("test htpasswd client check password", t, func() {
		username, _ := test.GenerateRandomString()
		password, _ := test.GenerateRandomString()

		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)

		client := api.NewHtpasswdClient(htpasswdPath)
		So(client.Init(), ShouldBeNil)

		Convey("check for non-existing login", func() {
			err := client.CheckPassword("non-existing", "password")
			So(err, ShouldEqual, zerr.ErrBadUser)
		})

		Convey("check with wrong password", func() {
			err := client.CheckPassword(username, "wrong_password")
			So(err, ShouldEqual, zerr.ErrPasswordsDoNotMatch)
		})

		Convey("check with correct password", func() {
			err := client.CheckPassword(username, password)
			So(err, ShouldBeNil)
		})
	})
}

func TestHtpasswdClient_Init(t *testing.T) {
	username, _ := test.GenerateRandomString()
	password, _ := test.GenerateRandomString()

	htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
	defer os.Remove(htpasswdPath)

	Convey("test htpasswd client init", t, func() {
		Convey("file does not exist", func() {
			client := api.NewHtpasswdClient("non-existing/path")
			err := client.Init()
			So(err, ShouldBeError,
				"error occurred while opening creds-file: open non-existing/path: no such file or directory")
		})

		Convey("file exists, bad format", func() {
			htpasswdPath := test.MakeHtpasswdFileFromString("random text")
			defer os.Remove(htpasswdPath)

			client := api.NewHtpasswdClient(htpasswdPath)
			err := client.Init()
			So(err, ShouldBeNil)
		})

		Convey("file exists, contains username:password", func() {
			client := api.NewHtpasswdClient(htpasswdPath)
			err := client.Init()
			So(err, ShouldBeNil)

			gotPasshprase, ok := client.Get(username)
			So(ok, ShouldBeTrue)
			So(bcrypt.CompareHashAndPassword([]byte(gotPasshprase), []byte(password)), ShouldBeNil)
		})
	})
}
