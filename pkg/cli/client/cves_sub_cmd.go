//go:build search
// +build search

package client

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	zerr "zotregistry.dev/zot/errors"
	zcommon "zotregistry.dev/zot/pkg/common"
)

const (
	maxRetries = 20
)

func NewCveForImageCommand(searchService SearchService) *cobra.Command {
	var (
		searchedCVEID   string
		cveListSortFlag = CVEListSortFlag(SortBySeverity)
	)

	cveForImageCmd := &cobra.Command{
		Use:   "list [repo:tag]|[repo@digest]",
		Short: "List CVEs by REPO:TAG or REPO@DIGEST",
		Long:  `List CVEs by REPO:TAG or REPO@DIGEST`,
		Args:  OneImageWithRefArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			err = CheckExtEndPointQuery(searchConfig, CVEListForImageQuery())
			if err != nil {
				return fmt.Errorf("%w: '%s'", err, CVEListForImageQuery().Name)
			}

			image := args[0]

			return SearchCVEForImageGQL(searchConfig, image, searchedCVEID)
		},
	}

	cveForImageCmd.Flags().StringVar(&searchedCVEID, SearchedCVEID, "", "Search for a specific CVE by name/id")
	cveForImageCmd.Flags().Var(&cveListSortFlag, SortByFlag,
		fmt.Sprintf("Options for sorting the output: [%s]", CVEListSortOptionsStr()))

	return cveForImageCmd
}

func NewImagesByCVEIDCommand(searchService SearchService) *cobra.Command {
	var (
		repo              string
		imageListSortFlag = ImageListSortFlag(SortByAlphabeticAsc)
	)

	imagesByCVEIDCmd := &cobra.Command{
		Use:   "affected [cveId]",
		Short: "List images affected by a CVE",
		Long:  `List images affected by a CVE`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}

			if !strings.HasPrefix(args[0], "CVE") {
				return fmt.Errorf("%w: expected a cveid 'CVE-...' got '%s'", zerr.ErrInvalidCLIParameter, args[0])
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			err = CheckExtEndPointQuery(searchConfig, ImageListForCVEQuery())
			if err != nil {
				return fmt.Errorf("%w: '%s'", err, ImageListForCVEQuery().Name)
			}

			searchedCVEID := args[0]

			return SearchImagesByCVEIDGQL(searchConfig, repo, searchedCVEID)
		},
	}

	imagesByCVEIDCmd.Flags().StringVar(&repo, "repo", "", "Search for a specific CVE by name/id")
	imagesByCVEIDCmd.Flags().Var(&imageListSortFlag, SortByFlag,
		fmt.Sprintf("Options for sorting the output: [%s]", ImageListSortOptionsStr()))

	return imagesByCVEIDCmd
}

func NewFixedTagsCommand(searchService SearchService) *cobra.Command {
	imageListSortFlag := ImageListSortFlag(SortByAlphabeticAsc)

	fixedTagsCmd := &cobra.Command{
		Use:   "fixed [repo] [cveId]",
		Short: "List tags where a CVE is fixed",
		Long:  `List tags where a CVE is fixed`,
		Args: func(cmd *cobra.Command, args []string) error {
			const argCount = 2

			if err := cobra.ExactArgs(argCount)(cmd, args); err != nil {
				return err
			}

			if !zcommon.CheckIsCorrectRepoNameFormat(args[0]) {
				return fmt.Errorf("%w: expected a valid repo name for first argument '%s'", zerr.ErrInvalidCLIParameter, args[0])
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			err = CheckExtEndPointQuery(searchConfig, ImageListWithCVEFixedQuery())
			if err != nil {
				return fmt.Errorf("%w: '%s'", err, ImageListWithCVEFixedQuery().Name)
			}

			repo := args[0]
			searchedCVEID := args[1]

			return SearchFixedTagsGQL(searchConfig, repo, searchedCVEID)
		},
	}

	fixedTagsCmd.Flags().Var(&imageListSortFlag, SortByFlag,
		fmt.Sprintf("Options for sorting the output: [%s]", ImageListSortOptionsStr()))

	return fixedTagsCmd
}

func NewCVEDiffCommand(searchService SearchService) *cobra.Command {
	var (
		minuendStr, minuendArch       string
		subtrahendStr, subtrahendArch string
	)
	imagesByCVEIDCmd := &cobra.Command{
		Use:   "diff [minuend] ([minuend-platform]) [subtrahend] ([subtrahend-platform])",
		Short: "List the CVE's present in minuend that are not present in subtrahend",
		Long:  `List the CVE's present in minuend that are not present in subtrahend`,
		Args: func(cmd *cobra.Command, args []string) error {
			const (
				twoArgs   = 2
				threeArgs = 3
				fourArgs  = 4
			)

			if err := cobra.RangeArgs(twoArgs, fourArgs)(cmd, args); err != nil {
				return err
			}

			if !isRepoTag(args[0]) {
				return fmt.Errorf("%w: first parameter should be a repo:tag", zerr.ErrInvalidArgs)
			}

			minuendStr = args[0]

			if isRepoTag(args[1]) {
				subtrahendStr = args[1]
			} else {
				minuendArch = args[1]

				if len(args) == twoArgs {
					return fmt.Errorf("%w: not enough arguments, specified only 1 image with arch", zerr.ErrInvalidArgs)
				}
			}

			if len(args) == twoArgs {
				return nil
			}

			if isRepoTag(args[2]) {
				if subtrahendStr == "" {
					subtrahendStr = args[2]
				} else {
					return fmt.Errorf("%w: too many repo:tag inputs", zerr.ErrInvalidArgs)
				}
			} else {
				if subtrahendStr == "" {
					return fmt.Errorf("%w: 3rd argument should be a repo:tag", zerr.ErrInvalidArgs)
				} else {
					subtrahendArch = args[2]
				}
			}

			if len(args) == threeArgs {
				return nil
			}

			if isRepoTag(args[3]) {
				return fmt.Errorf("%w: 4th argument should not be a repo:tag but an arch", zerr.ErrInvalidArgs)
			} else {
				subtrahendArch = args[3]
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			err = CheckExtEndPointQuery(searchConfig, CVEDiffListForImagesQuery())
			if err != nil {
				return fmt.Errorf("%w: '%s'", err, CVEDiffListForImagesQuery().Name)
			}

			// parse the args and determine the input
			minuend := getImageIdentifier(minuendStr, minuendArch)
			subtrahend := getImageIdentifier(subtrahendStr, subtrahendArch)

			return SearchCVEDiffList(searchConfig, minuend, subtrahend)
		},
	}

	return imagesByCVEIDCmd
}

func isRepoTag(arg string) bool {
	_, _, _, err := zcommon.GetRepoReference(arg) //nolint:dogsled

	return err == nil
}

type osArch struct {
	Os   string
	Arch string
}

type ImageIdentifier struct {
	Repo     string  `json:"repo"`
	Tag      string  `json:"tag"`
	Digest   string  `json:"digest"`
	Platform *osArch `json:"platform"`
}

func getImageIdentifier(repoTagStr, platformStr string) ImageIdentifier {
	var tag, digest string

	repo, ref, isTag, err := zcommon.GetRepoReference(repoTagStr)
	if err != nil {
		return ImageIdentifier{}
	}

	if isTag {
		tag = ref
	} else {
		digest = ref
	}

	// check if the following input is a repo:tag or repo@digest, if not then it's a platform
	var platform *osArch

	if platformStr != "" {
		os, arch, _ := strings.Cut(platformStr, "/")
		platform = &osArch{Os: os, Arch: arch}
	}

	return ImageIdentifier{
		Repo:     repo,
		Tag:      tag,
		Digest:   digest,
		Platform: platform,
	}
}
