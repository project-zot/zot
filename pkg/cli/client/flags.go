//go:build search
// +build search

package client

import (
	"fmt"
	"strings"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/common"
)

const (
	URLFlag          = "url"
	ConfigFlag       = "config"
	UserFlag         = "user"
	OutputFormatFlag = "format"
	FixedFlag        = "fixed"
	VerboseFlag      = "verbose"
	VersionFlag      = "version"
	DebugFlag        = "debug"
	SearchedCVEID    = "cve-id"
	SortByFlag       = "sort-by"
	PlatformFlag     = "platform"
)

const (
	SortByRelevance     = "relevance"
	SortByUpdateTime    = "update-time"
	SortByAlphabeticAsc = "alpha-asc"
	SortByAlphabeticDsc = "alpha-dsc"
	SortBySeverity      = "severity"
)

const stringType = "string"

func ImageListSortOptions() []string {
	return []string{SortByUpdateTime, SortByAlphabeticAsc, SortByAlphabeticDsc}
}

func ImageListSortOptionsStr() string {
	return strings.Join(ImageListSortOptions(), ", ")
}

func ImageSearchSortOptions() []string {
	return []string{SortByRelevance, SortByUpdateTime, SortByAlphabeticAsc, SortByAlphabeticDsc}
}

func ImageSearchSortOptionsStr() string {
	return strings.Join(ImageSearchSortOptions(), ", ")
}

func CVEListSortOptions() []string {
	return []string{SortByAlphabeticAsc, SortByAlphabeticDsc, SortBySeverity}
}

func CVEListSortOptionsStr() string {
	return strings.Join(CVEListSortOptions(), ", ")
}

func RepoListSortOptions() []string {
	return []string{SortByAlphabeticAsc, SortByAlphabeticDsc}
}

func RepoListSortOptionsStr() string {
	return strings.Join(RepoListSortOptions(), ", ")
}

func Flag2SortCriteria(sortBy string) string {
	switch sortBy {
	case SortByRelevance:
		return "RELEVANCE"
	case SortByUpdateTime:
		return "UPDATE_TIME"
	case SortByAlphabeticAsc:
		return "ALPHABETIC_ASC"
	case SortByAlphabeticDsc:
		return "ALPHABETIC_DSC"
	case SortBySeverity:
		return "SEVERITY"
	default:
		return "BAD_SORT_CRITERIA"
	}
}

type CVEListSortFlag string

func (e *CVEListSortFlag) String() string {
	return string(*e)
}

func (e *CVEListSortFlag) Set(val string) error {
	if !common.Contains(CVEListSortOptions(), val) {
		return fmt.Errorf("%w %s", zerr.ErrFlagValueUnsupported, CVEListSortOptionsStr())
	}

	*e = CVEListSortFlag(val)

	return nil
}

func (e *CVEListSortFlag) Type() string {
	return stringType
}

type ImageListSortFlag string

func (e *ImageListSortFlag) String() string {
	return string(*e)
}

func (e *ImageListSortFlag) Set(val string) error {
	if !common.Contains(ImageListSortOptions(), val) {
		return fmt.Errorf("%w %s", zerr.ErrFlagValueUnsupported, ImageListSortOptionsStr())
	}

	*e = ImageListSortFlag(val)

	return nil
}

func (e *ImageListSortFlag) Type() string {
	return stringType
}

type ImageSearchSortFlag string

func (e *ImageSearchSortFlag) String() string {
	return string(*e)
}

func (e *ImageSearchSortFlag) Set(val string) error {
	if !common.Contains(ImageSearchSortOptions(), val) {
		return fmt.Errorf("%w %s", zerr.ErrFlagValueUnsupported, ImageSearchSortOptionsStr())
	}

	*e = ImageSearchSortFlag(val)

	return nil
}

func (e *ImageSearchSortFlag) Type() string {
	return stringType
}

type RepoListSortFlag string

func (e *RepoListSortFlag) String() string {
	return string(*e)
}

func (e *RepoListSortFlag) Set(val string) error {
	if !common.Contains(RepoListSortOptions(), val) {
		return fmt.Errorf("%w %s", zerr.ErrFlagValueUnsupported, RepoListSortOptionsStr())
	}

	*e = RepoListSortFlag(val)

	return nil
}

func (e *RepoListSortFlag) Type() string {
	return stringType
}
