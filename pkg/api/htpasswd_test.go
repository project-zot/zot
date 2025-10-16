package api_test

import (
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/log"
	test "zotregistry.dev/zot/v2/pkg/test/common"
)

func TestHTPasswdWatcher(t *testing.T) {
	logger := log.NewLogger("DEBUG", "")

	Convey("reload htpasswd", t, func(c C) {
		username, _ := test.GenerateRandomString()
		password1, _ := test.GenerateRandomString()
		password2, _ := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password1))

		defer os.Remove(htpasswdPath)

		htp := api.NewHTPasswd(logger)

		htw, err := api.NewHTPasswdWatcher(htp, "")
		So(err, ShouldBeNil)

		defer htw.Close() //nolint: errcheck

		_, present := htp.Get(username)
		So(present, ShouldBeFalse)

		err = htw.ChangeFile(htpasswdPath)
		So(err, ShouldBeNil)

		// 1. Check user present and it has password1
		ok, present := htp.Authenticate(username, password1)
		So(ok, ShouldBeTrue)
		So(present, ShouldBeTrue)

		ok, present = htp.Authenticate(username, password2)
		So(ok, ShouldBeFalse)
		So(present, ShouldBeTrue)

		// 2. Change file
		err = os.WriteFile(htpasswdPath, []byte(test.GetCredString(username, password2)), 0o600)
		So(err, ShouldBeNil)

		// 3. Give some time for the background task
		time.Sleep(10 * time.Millisecond)

		// 4. Check user present and now has password2
		ok, present = htp.Authenticate(username, password1)
		So(ok, ShouldBeFalse)
		So(present, ShouldBeTrue)

		ok, present = htp.Authenticate(username, password2)
		So(ok, ShouldBeTrue)
		So(present, ShouldBeTrue)
	})
}
