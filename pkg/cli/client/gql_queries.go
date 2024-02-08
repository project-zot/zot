//go:build search
// +build search

package client

type GQLField struct {
	Name string
	Type GQLType
}

type GQLType struct {
	Name   string
	Fields []GQLField
}

type GQLQuery struct {
	Name       string
	Args       []string
	ReturnType GQLType
}

func CVEResultForImage() GQLType {
	return GQLType{
		Name: "CVEResultForImage",
	}
}

func CVEDiffResult() GQLType {
	return GQLType{
		Name: "CVEDiffResult",
	}
}

func PaginatedImagesResult() GQLType {
	return GQLType{
		Name: "PaginatedImagesResult",
	}
}

func Referrer() GQLType {
	return GQLType{
		Name: "Referrer",
	}
}

func GlobalSearchResult() GQLType {
	return GQLType{
		Name: "GlobalSearchResult",
	}
}

func ImageListQuery() GQLQuery {
	return GQLQuery{
		Name:       "ImageList",
		Args:       []string{"repo", "requestedPage"},
		ReturnType: PaginatedImagesResult(),
	}
}

func CVEDiffListForImagesQuery() GQLQuery {
	return GQLQuery{
		Name:       "CVEDiffListForImages",
		Args:       []string{"minuend", "subtrahend", "requestedPage", "searchedCVE", "excludedCVE"},
		ReturnType: CVEDiffResult(),
	}
}

func ImageListForDigestQuery() GQLQuery {
	return GQLQuery{
		Name:       "ImageListForDigest",
		Args:       []string{"id", "requestedPage"},
		ReturnType: PaginatedImagesResult(),
	}
}

func BaseImageListQuery() GQLQuery {
	return GQLQuery{
		Name:       "BaseImageList",
		Args:       []string{"image", "digest", "requestedPage"},
		ReturnType: PaginatedImagesResult(),
	}
}

func DerivedImageListQuery() GQLQuery {
	return GQLQuery{
		Name:       "DerivedImageList",
		Args:       []string{"image", "digest", "requestedPage"},
		ReturnType: PaginatedImagesResult(),
	}
}

func CVEListForImageQuery() GQLQuery {
	return GQLQuery{
		Name:       "CVEListForImage",
		Args:       []string{"image", "requestedPage", "searchedCVE", "excludedCVE", "severity"},
		ReturnType: CVEResultForImage(),
	}
}

func ImageListForCVEQuery() GQLQuery {
	return GQLQuery{
		Name:       "ImageListForCVE",
		Args:       []string{"id", "filter", "requestedPage"},
		ReturnType: PaginatedImagesResult(),
	}
}

func ImageListWithCVEFixedQuery() GQLQuery {
	return GQLQuery{
		Name:       "ImageListWithCVEFixed",
		Args:       []string{"id", "image", "filter", "requestedPage"},
		ReturnType: PaginatedImagesResult(),
	}
}

func ReferrersQuery() GQLQuery {
	return GQLQuery{
		Name:       "Referrers",
		Args:       []string{"repo", "digest", "type"},
		ReturnType: Referrer(),
	}
}

func GlobalSearchQuery() GQLQuery {
	return GQLQuery{
		Name:       "GlobalSearch",
		Args:       []string{"query", "filter", "requestedPage"},
		ReturnType: GlobalSearchResult(),
	}
}
