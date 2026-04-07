package constants_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"zotregistry.dev/zot/v2/pkg/api/constants"
	zreg "zotregistry.dev/zot/v2/pkg/regexp"
)

func TestMaxManifestDigestQueryTagsDerived(t *testing.T) {
	t.Parallel()

	want := (8192 - 2048) / (len("tag=") + zreg.TagMaxLen + 1)

	assert.Equal(t, want, constants.MaxManifestDigestQueryTags)
}
