package ociutils_test

import (
	"context"
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/mocks"
	ociutils "zotregistry.dev/zot/pkg/test/oci-utils"
)

var ErrTestFail = fmt.Errorf("fail")

func TestInitializeMetaDBErrors(t *testing.T) {
	ctx := context.Background()

	Convey("InitializeTestMetaDB", t, func() {
		metaDB := mocks.MetaDBMock{
			GetRepoMetaFn: func(ctx context.Context, repo string) (types.RepoMeta, error) {
				return types.RepoMeta{
					Statistics: map[string]types.DescriptorStatistics{},
					Signatures: map[string]types.ManifestSignatures{},
					Referrers:  map[string][]types.ReferrerInfo{},
				}, nil
			},
		}

		Convey("Multiple repos same name", func() {
			_, err := ociutils.InitializeTestMetaDB(ctx, metaDB, ociutils.Repo{Name: "repo"}, ociutils.Repo{Name: "repo"})
			So(err, ShouldNotBeNil)
		})
		Convey("Set Repo Ref fails", func() {
			metaDB.SetRepoReferenceFn = func(ctx context.Context, repo, reference string, imageMeta types.ImageMeta) error {
				return ErrTestFail
			}
			_, err := ociutils.InitializeTestMetaDB(ctx, metaDB,
				ociutils.Repo{Name: "repo", Images: []ociutils.RepoImage{{}}},
			)
			So(err, ShouldNotBeNil)
		})
		Convey("Set Repo Ref fails for manifest in index", func() {
			metaDB.SetRepoReferenceFn = func(ctx context.Context, repo, reference string, imageMeta types.ImageMeta) error {
				return ErrTestFail
			}
			_, err := ociutils.InitializeTestMetaDB(ctx, metaDB,
				ociutils.Repo{
					Name:            "repo",
					MultiArchImages: []ociutils.RepoMultiArchImage{{MultiarchImage: image.CreateRandomMultiarch()}},
				},
			)
			So(err, ShouldNotBeNil)
		})
		Convey("Set Repo Ref fails for index", func() {
			count := 0
			metaDB.SetRepoReferenceFn = func(ctx context.Context, repo, reference string, imageMeta types.ImageMeta) error {
				if count == 1 {
					return ErrTestFail
				}

				count++

				return nil
			}

			multiarch := image.CreateMultiarchWith().Images([]image.Image{{}}).Build()
			_, err := ociutils.InitializeTestMetaDB(ctx, metaDB,
				ociutils.Repo{
					Name:            "repo",
					MultiArchImages: []ociutils.RepoMultiArchImage{{MultiarchImage: multiarch}},
				},
			)
			So(err, ShouldNotBeNil)
		})
		Convey("Get repo meta errors", func() {
			metaDB.GetRepoMetaFn = func(ctx context.Context, repo string) (types.RepoMeta, error) {
				return types.RepoMeta{}, ErrTestFail
			}
			_, err := ociutils.InitializeTestMetaDB(ctx, metaDB,
				ociutils.Repo{Name: "repo", Images: []ociutils.RepoImage{{}}},
			)
			So(err, ShouldNotBeNil)
		})
		Convey("Set repo meta errors", func() {
			metaDB.SetRepoMetaFn = func(repo string, repoMeta types.RepoMeta) error {
				return ErrTestFail
			}
			_, err := ociutils.InitializeTestMetaDB(ctx, metaDB,
				ociutils.Repo{Name: "repo", Images: []ociutils.RepoImage{{}}},
			)
			So(err, ShouldNotBeNil)
		})
		Convey("ToggleBookmarkRepo errors", func() {
			metaDB.ToggleBookmarkRepoFn = func(ctx context.Context, repo string) (types.ToggleState, error) {
				return types.NotChanged, ErrTestFail
			}
			_, err := ociutils.InitializeTestMetaDB(ctx, metaDB,
				ociutils.Repo{Name: "repo", Images: []ociutils.RepoImage{{}}, IsBookmarked: true},
			)
			So(err, ShouldNotBeNil)
		})
		Convey("ToggleStarRepo errors", func() {
			metaDB.ToggleStarRepoFn = func(ctx context.Context, repo string) (types.ToggleState, error) {
				return types.NotChanged, ErrTestFail
			}
			_, err := ociutils.InitializeTestMetaDB(ctx, metaDB,
				ociutils.Repo{Name: "repo", Images: []ociutils.RepoImage{{}}, IsStarred: true},
			)
			So(err, ShouldNotBeNil)
		})
	})
}
