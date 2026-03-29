package constants_test

import (
	"testing"

	"zotregistry.dev/zot/v2/pkg/api/constants"
	zreg "zotregistry.dev/zot/v2/pkg/regexp"
)

func TestMaxManifestDigestQueryTagsDerived(t *testing.T) {
	t.Parallel()

	want := (8192 - 2048) / (len("tag=") + zreg.TagMaxLen + 1)

	if constants.MaxManifestDigestQueryTags != want {
		t.Fatalf("MaxManifestDigestQueryTags = %d, want %d", constants.MaxManifestDigestQueryTags, want)
	}
}
