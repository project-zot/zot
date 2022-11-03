package convert_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/99designs/gqlgen/graphql"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/extensions/search/convert"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	"zotregistry.io/zot/pkg/meta/repodb"
	bolt "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("TestError")

func TestConvertErrors(t *testing.T) {
	Convey("", t, func() {
		repoDB, err := bolt.NewBoltDBWrapper(bolt.DBParameters{
			RootDir: t.TempDir(),
		})
		So(err, ShouldBeNil)

		configBlob, err := json.Marshal(ispec.Image{})
		So(err, ShouldBeNil)

		manifestBlob, err := json.Marshal(ispec.Manifest{
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayerGzip,
					Size:      0,
					Digest:    godigest.NewDigestFromEncoded(godigest.SHA256, "digest"),
				},
			},
		})
		So(err, ShouldBeNil)

		repoMeta11 := repodb.ManifestMetadata{
			ManifestBlob: manifestBlob,
			ConfigBlob:   configBlob,
		}

		digest11 := godigest.FromString("abc1")
		err = repoDB.SetManifestMeta("repo1", digest11, repoMeta11)
		So(err, ShouldBeNil)
		err = repoDB.SetRepoTag("repo1", "0.1.0", digest11, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)

		repoMetas, manifestMetaMap, err := repoDB.SearchRepos(context.Background(), "", repodb.Filter{}, repodb.PageInput{})
		So(err, ShouldBeNil)

		ctx := graphql.WithResponseContext(context.Background(),
			graphql.DefaultErrorPresenter, graphql.DefaultRecover)

		_ = convert.RepoMeta2RepoSummary(
			ctx,
			repoMetas[0],
			manifestMetaMap,
			convert.SkipQGLField{},
			mocks.CveInfoMock{
				GetCVESummaryForImageFn: func(image string) (cveinfo.ImageCVESummary, error) {
					return cveinfo.ImageCVESummary{}, ErrTestError
				},
			},
		)

		So(graphql.GetErrors(ctx).Error(), ShouldContainSubstring, "unable to run vulnerability scan on tag")
	})
}
