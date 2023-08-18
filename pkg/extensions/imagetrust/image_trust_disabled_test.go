//go:build !imagetrust

package imagetrust_test

import (
	"os"
	"path"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/extensions/imagetrust"
)

func TestImageTrust(t *testing.T) {
	Convey("binary doesn't include imagetrust", t, func() {
		rootDir := t.TempDir()

		err := imagetrust.InitCosignDir(rootDir)
		So(err, ShouldBeNil)

		cosignDir := path.Join(rootDir, "_cosign")
		_, err = os.Stat(cosignDir)
		So(os.IsNotExist(err), ShouldBeTrue)

		err = imagetrust.InitNotationDir(rootDir)
		So(err, ShouldBeNil)

		notationDir := path.Join(rootDir, "_notation")
		_, err = os.Stat(notationDir)
		So(os.IsNotExist(err), ShouldBeTrue)

		err = imagetrust.InitCosignAndNotationDirs(rootDir)
		So(err, ShouldBeNil)

		_, err = os.Stat(cosignDir)
		So(os.IsNotExist(err), ShouldBeTrue)
		_, err = os.Stat(notationDir)
		So(os.IsNotExist(err), ShouldBeTrue)

		author, expTime, ok, err := imagetrust.VerifySignature("", []byte{}, "", "", []byte{}, "")
		So(author, ShouldBeEmpty)
		So(expTime, ShouldBeZeroValue)
		So(ok, ShouldBeFalse)
		So(err, ShouldBeNil)
	})
}
