//go:build search
// +build search

package client

import (
	"fmt"

	"github.com/spf13/cobra"

	zerr "zotregistry.dev/zot/errors"
	zcommon "zotregistry.dev/zot/pkg/common"
)

func NewSearchSubjectCommand(searchService SearchService) *cobra.Command {
	imageListSortFlag := ImageListSortFlag(SortByAlphabeticAsc)

	cmd := &cobra.Command{
		Use:   "subject [repo:tag]|[repo@digest]",
		Short: "List all referrers for this subject.",
		Long: `List all referrers for this subject. The subject can be specified by tag(repo:tag) or by digest" +
			"(repo@digest)`,
		Example: `# For referrers search specify the referred subject using it's full digest or tag:
  zli search subject "repo@sha256:f9a0981..."
  zli search subject "repo:tag"`,
		Args: OneImageWithRefArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			if err := CheckExtEndPointQuery(searchConfig, ReferrersQuery()); err == nil {
				return SearchReferrersGQL(searchConfig, args[0])
			} else {
				return SearchReferrers(searchConfig, args[0])
			}
		},
	}

	cmd.Flags().Var(&imageListSortFlag, SortByFlag,
		fmt.Sprintf("Options for sorting the output: [%s]", ImageListSortOptionsStr()))

	return cmd
}

func NewSearchQueryCommand(searchService SearchService) *cobra.Command {
	imageSearchSortFlag := ImageSearchSortFlag(SortByRelevance)

	cmd := &cobra.Command{
		Use:   "query [repo]|[repo:tag]",
		Short: "Fuzzy search for repos and their tags.",
		Long:  "Fuzzy search for repos and their tags.",
		Example: `# For repo search specify a substring of the repo name without the tag
  zli search query "test/repo"

# For image search specify the full repo name followed by the tag or a prefix of the tag.
  zli search query "test/repo:2.1."`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			// special format for searching all images and tags
			if args[0] == ":" {
				err := CheckExtEndPointQuery(searchConfig, GlobalSearchQuery())
				if err != nil {
					return fmt.Errorf("%w: '%s'", err, ImageListQuery().Name)
				}

				return SearchAllImagesGQL(searchConfig)
			}

			if err := CheckExtEndPointQuery(searchConfig, GlobalSearchQuery()); err != nil {
				return fmt.Errorf("%w: '%s'", err, GlobalSearchQuery().Name)
			}

			return GlobalSearchGQL(searchConfig, args[0])
		},
	}

	cmd.Flags().Var(&imageSearchSortFlag, SortByFlag,
		fmt.Sprintf("Options for sorting the output: [%s]", ImageSearchSortOptionsStr()))

	return cmd
}

func OneImageWithRefArg(cmd *cobra.Command, args []string) error {
	if err := cobra.ExactArgs(1)(cmd, args); err != nil {
		return err
	}

	image := args[0]

	if dir, ref, _ := zcommon.GetImageDirAndReference(image); dir == "" || ref == "" {
		return zerr.ErrInvalidRepoRefFormat
	}

	return nil
}
