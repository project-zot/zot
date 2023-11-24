package convert

import (
	"context"

	"github.com/99designs/gqlgen/graphql"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/vektah/gqlparser/v2/gqlerror"

	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
)

func updateRepoSummaryVulnerabilities(
	ctx context.Context,
	repoSummary *gql_generated.RepoSummary,
	skip SkipQGLField,
	cveInfo cveinfo.CveInfo,
) {
	if repoSummary == nil {
		return
	}

	updateImageSummaryVulnerabilities(ctx, repoSummary.NewestImage, skip, cveInfo)
}

func updateImageSummaryVulnerabilities(
	ctx context.Context,
	imageSummary *gql_generated.ImageSummary,
	skip SkipQGLField,
	cveInfo cveinfo.CveInfo,
) {
	if imageSummary == nil {
		return
	}

	imageCveSummary := cvemodel.ImageCVESummary{}

	imageSummary.Vulnerabilities = &gql_generated.ImageVulnerabilitySummary{
		MaxSeverity: &imageCveSummary.MaxSeverity,
		Count:       &imageCveSummary.Count,
	}

	// Check if vulnerability scanning is disabled
	if cveInfo == nil || skip.Vulnerabilities {
		return
	}

	imageCveSummary, err := cveInfo.GetCVESummaryForImageMedia(ctx, *imageSummary.RepoName, *imageSummary.Digest,
		*imageSummary.MediaType)
	if err != nil {
		// Log the error, but we should still include the image in results
		graphql.AddError(
			ctx,
			gqlerror.Errorf(
				"unable to run vulnerability scan on tag %s in repo %s: error: %s",
				*imageSummary.Tag, *imageSummary.RepoName, err.Error(),
			),
		)
	}

	imageSummary.Vulnerabilities.MaxSeverity = &imageCveSummary.MaxSeverity
	imageSummary.Vulnerabilities.Count = &imageCveSummary.Count

	for _, manifestSummary := range imageSummary.Manifests {
		updateManifestSummaryVulnerabilities(ctx, manifestSummary, *imageSummary.RepoName, skip, cveInfo)
	}
}

func updateManifestSummaryVulnerabilities(
	ctx context.Context,
	manifestSummary *gql_generated.ManifestSummary,
	repoName string,
	skip SkipQGLField,
	cveInfo cveinfo.CveInfo,
) {
	if manifestSummary == nil {
		return
	}

	imageCveSummary := cvemodel.ImageCVESummary{}

	manifestSummary.Vulnerabilities = &gql_generated.ImageVulnerabilitySummary{
		MaxSeverity: &imageCveSummary.MaxSeverity,
		Count:       &imageCveSummary.Count,
	}

	// Check if vulnerability scanning is disabled
	if cveInfo == nil || skip.Vulnerabilities {
		return
	}

	imageCveSummary, err := cveInfo.GetCVESummaryForImageMedia(ctx, repoName, *manifestSummary.Digest,
		ispec.MediaTypeImageManifest)
	if err != nil {
		// Log the error, but we should still include the manifest in results
		graphql.AddError(
			ctx,
			gqlerror.Errorf(
				"unable to run vulnerability scan in repo %s: manifest digest: %s, error: %s",
				repoName, *manifestSummary.Digest, err.Error(),
			),
		)
	}

	manifestSummary.Vulnerabilities.MaxSeverity = &imageCveSummary.MaxSeverity
	manifestSummary.Vulnerabilities.Count = &imageCveSummary.Count
}
