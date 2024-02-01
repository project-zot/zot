//go:build search
// +build search

package client

import (
	"fmt"

	"github.com/spf13/cobra"

	zerr "zotregistry.dev/zot/errors"
	zcommon "zotregistry.dev/zot/pkg/common"
)

func NewImageListCommand(searchService SearchService) *cobra.Command {
	imageListSortFlag := ImageListSortFlag(SortByAlphabeticAsc)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all images",
		Long:  "List all images",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			if err := CheckExtEndPointQuery(searchConfig, ImageListQuery()); err == nil {
				return SearchAllImagesGQL(searchConfig)
			}

			return SearchAllImages(searchConfig)
		},
	}

	cmd.Flags().Var(&imageListSortFlag, SortByFlag,
		fmt.Sprintf("Options for sorting the output: [%s]", ImageListSortOptionsStr()))

	return cmd
}

func NewImageCVEListCommand(searchService SearchService) *cobra.Command {
	var (
		searchedCVEID   string
		cveListSortFlag = CVEListSortFlag(SortBySeverity)
	)

	cmd := &cobra.Command{
		Use:   "cve [repo]|[repo-name:tag]|[repo-name@digest]",
		Short: "List all CVE's of the image",
		Long:  "List all CVE's of the image",
		Args:  OneImageWithRefArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			if err := CheckExtEndPointQuery(searchConfig, CVEListForImageQuery()); err == nil {
				image := args[0]

				return SearchCVEForImageGQL(searchConfig, image, searchedCVEID)
			} else {
				return err
			}
		},
	}

	cmd.Flags().StringVar(&searchedCVEID, SearchedCVEID, "", "Search for a specific CVE by name/id")
	cmd.Flags().Var(&cveListSortFlag, SortByFlag,
		fmt.Sprintf("Options for sorting the output: [%s]", CVEListSortOptionsStr()))

	return cmd
}

func NewImageDerivedCommand(searchService SearchService) *cobra.Command {
	imageListSortFlag := ImageListSortFlag(SortByAlphabeticAsc)

	cmd := &cobra.Command{
		Use:   "derived [repo-name:tag]|[repo-name@digest]",
		Short: "List images that are derived from given image",
		Long:  "List images that are derived from given image",
		Args:  OneImageWithRefArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			if err := CheckExtEndPointQuery(searchConfig, DerivedImageListQuery()); err == nil {
				return SearchDerivedImageListGQL(searchConfig, args[0])
			} else {
				return err
			}
		},
	}

	cmd.Flags().Var(&imageListSortFlag, SortByFlag,
		fmt.Sprintf("Options for sorting the output: [%s]", ImageListSortOptionsStr()))

	return cmd
}

func NewImageBaseCommand(searchService SearchService) *cobra.Command {
	imageListSortFlag := ImageListSortFlag(SortByAlphabeticAsc)

	cmd := &cobra.Command{
		Use:   "base [repo-name:tag]|[repo-name@digest]",
		Short: "List images that are base for the given image",
		Long:  "List images that are base for the given image",
		Args:  OneImageWithRefArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			if err := CheckExtEndPointQuery(searchConfig, BaseImageListQuery()); err == nil {
				return SearchBaseImageListGQL(searchConfig, args[0])
			} else {
				return err
			}
		},
	}

	cmd.Flags().Var(&imageListSortFlag, SortByFlag,
		fmt.Sprintf("Options for sorting the output: [%s]", ImageListSortOptionsStr()))

	return cmd
}

func NewImageDigestCommand(searchService SearchService) *cobra.Command {
	imageListSortFlag := ImageListSortFlag(SortByAlphabeticAsc)

	cmd := &cobra.Command{
		Use:   "digest [digest]",
		Short: "List images that contain a blob(manifest, config or layer) with the given digest",
		Long:  "List images that contain a blob(manifest, config or layer) with the given digest",
		Example: `zli image digest 8a1930f0
zli image digest sha256:8a1930f0...`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			if err := CheckExtEndPointQuery(searchConfig, ImageListForDigestQuery()); err == nil {
				return SearchImagesForDigestGQL(searchConfig, args[0])
			} else {
				return err
			}
		},
	}

	cmd.Flags().Var(&imageListSortFlag, SortByFlag,
		fmt.Sprintf("Options for sorting the output: [%s]", ImageListSortOptionsStr()))

	return cmd
}

func NewImageNameCommand(searchService SearchService) *cobra.Command {
	imageListSortFlag := ImageListSortFlag(SortByAlphabeticAsc)

	cmd := &cobra.Command{
		Use:   "name [repo:tag]",
		Short: "List image details by name",
		Long:  "List image details by name",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}

			image := args[0]

			if dir, _ := zcommon.GetImageDirAndTag(image); dir == "" {
				return zerr.ErrInvalidRepoRefFormat
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			if err := CheckExtEndPointQuery(searchConfig, ImageListQuery()); err == nil {
				return SearchImageByNameGQL(searchConfig, args[0])
			}

			return SearchImageByName(searchConfig, args[0])
		},
	}

	cmd.Flags().Var(&imageListSortFlag, SortByFlag,
		fmt.Sprintf("Options for sorting the output: [%s]", ImageListSortOptionsStr()))

	return cmd
}
