//go:build search
// +build search

package client

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	zerr "zotregistry.dev/zot/errors"
	zcommon "zotregistry.dev/zot/pkg/common"
)

const CveDBRetryInterval = 3

func SearchAllImages(config SearchConfig) error {
	username, password := getUsernameAndPassword(config.User)
	imageErr := make(chan stringResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.SearchService.getAllImages(ctx, config, username, password, imageErr, &wg)
	wg.Add(1)

	errCh := make(chan error, 1)

	go collectResults(config, &wg, imageErr, cancel, printImageTableHeader, errCh)
	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func SearchAllImagesGQL(config SearchConfig) error {
	username, password := getUsernameAndPassword(config.User)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	imageList, err := config.SearchService.getImagesGQL(ctx, config, username, password, "")
	if err != nil {
		return err
	}

	imageListData := []imageStruct{}

	for _, image := range imageList.Results {
		imageListData = append(imageListData, imageStruct(image))
	}

	return printImageResult(config, imageListData)
}

func SearchImageByName(config SearchConfig, image string) error {
	username, password := getUsernameAndPassword(config.User)
	imageErr := make(chan stringResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.SearchService.getImageByName(ctx, config, username, password,
		image, imageErr, &wg)
	wg.Add(1)

	errCh := make(chan error, 1)
	go collectResults(config, &wg, imageErr, cancel, printImageTableHeader, errCh)

	wg.Wait()

	select {
	case err := <-errCh:
		if strings.Contains(err.Error(), "NAME_UNKNOWN") {
			return zerr.ErrEmptyRepoList
		}

		return err
	default:
		return nil
	}
}

func SearchImageByNameGQL(config SearchConfig, imageName string) error {
	username, password := getUsernameAndPassword(config.User)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	repo, tag := zcommon.GetImageDirAndTag(imageName)

	imageList, err := config.SearchService.getImagesGQL(ctx, config, username, password, repo)
	if err != nil {
		return err
	}

	imageListData := []imageStruct{}

	for _, image := range imageList.Results {
		if tag == "" || image.Tag == tag {
			imageListData = append(imageListData, imageStruct(image))
		}
	}

	return printImageResult(config, imageListData)
}

func SearchImagesByDigest(config SearchConfig, digest string) error {
	username, password := getUsernameAndPassword(config.User)
	imageErr := make(chan stringResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.SearchService.getImagesByDigest(ctx, config, username, password,
		digest, imageErr, &wg)
	wg.Add(1)

	errCh := make(chan error, 1)
	go collectResults(config, &wg, imageErr, cancel, printImageTableHeader, errCh)

	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func SearchDerivedImageListGQL(config SearchConfig, derivedImage string) error {
	username, password := getUsernameAndPassword(config.User)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	imageList, err := config.SearchService.getDerivedImageListGQL(ctx, config, username,
		password, derivedImage)
	if err != nil {
		return err
	}

	imageListData := []imageStruct{}

	for _, image := range imageList.DerivedImageList.Results {
		imageListData = append(imageListData, imageStruct(image))
	}

	return printImageResult(config, imageListData)
}

func SearchBaseImageListGQL(config SearchConfig, baseImage string) error {
	username, password := getUsernameAndPassword(config.User)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	imageList, err := config.SearchService.getBaseImageListGQL(ctx, config, username,
		password, baseImage)
	if err != nil {
		return err
	}

	imageListData := []imageStruct{}

	for _, image := range imageList.BaseImageList.Results {
		imageListData = append(imageListData, imageStruct(image))
	}

	return printImageResult(config, imageListData)
}

func SearchImagesForDigestGQL(config SearchConfig, digest string) error {
	username, password := getUsernameAndPassword(config.User)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	imageList, err := config.SearchService.getImagesForDigestGQL(ctx, config, username, password, digest)
	if err != nil {
		return err
	}

	imageListData := []imageStruct{}

	for _, image := range imageList.Results {
		imageListData = append(imageListData, imageStruct(image))
	}

	if err := printImageResult(config, imageListData); err != nil {
		return err
	}

	return nil
}

func SearchCVEForImageGQL(config SearchConfig, image, searchedCveID string) error {
	username, password := getUsernameAndPassword(config.User)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	var cveList *cveResult

	err := zcommon.RetryWithContext(ctx, func(attempt int, retryIn time.Duration) error {
		var err error

		cveList, err = config.SearchService.getCveByImageGQL(ctx, config, username, password, image, searchedCveID)
		if err != nil {
			if !strings.Contains(err.Error(), zerr.ErrCVEDBNotFound.Error()) {
				cancel()

				return err
			}

			fmt.Fprintf(config.ResultWriter,
				"[warning] CVE DB is not ready [%d] - retry in %d seconds\n", attempt, int(retryIn.Seconds()))
		}

		return err
	}, maxRetries, CveDBRetryInterval*time.Second)
	if err != nil {
		return err
	}

	if len(cveList.Data.CVEListForImage.CVEList) == 0 {
		fmt.Fprint(config.ResultWriter, "No CVEs found for image\n")

		return nil
	}

	var builder strings.Builder

	if config.OutputFormat == defaultOutputFormat || config.OutputFormat == "" {
		imageCVESummary := cveList.Data.CVEListForImage.Summary

		statsStr := fmt.Sprintf("CRITICAL %d, HIGH %d, MEDIUM %d, LOW %d, UNKNOWN %d, TOTAL %d\n\n",
			imageCVESummary.CriticalCount, imageCVESummary.HighCount, imageCVESummary.MediumCount,
			imageCVESummary.LowCount, imageCVESummary.UnknownCount, imageCVESummary.Count)

		fmt.Fprint(config.ResultWriter, statsStr)

		if !config.Verbose {
			printCVETableHeader(&builder)
			fmt.Fprint(config.ResultWriter, builder.String())
		}
	}

	out, err := cveList.string(config.OutputFormat, config.Verbose)
	if err != nil {
		return err
	}

	fmt.Fprint(config.ResultWriter, out)

	return nil
}

func SearchCVEDiffList(config SearchConfig, minuend, subtrahend ImageIdentifier) error {
	username, password := getUsernameAndPassword(config.User)

	response, err := config.SearchService.getCVEDiffListGQL(context.Background(), config, username, password,
		minuend, subtrahend)
	if err != nil {
		return err
	}

	cveDiffResult := response.Data.CveDiffResult

	result := cveResult{
		Data: cveData{
			CVEListForImage: cveListForImage{
				Tag:     cveDiffResult.Minuend.Tag,
				CVEList: cveDiffResult.CVEList,
				Summary: cveDiffResult.Summary,
			},
		},
	}

	var builder strings.Builder

	if config.OutputFormat == defaultOutputFormat || config.OutputFormat == "" {
		imageCVESummary := result.Data.CVEListForImage.Summary

		statsStr := fmt.Sprintf("CRITICAL %d, HIGH %d, MEDIUM %d, LOW %d, UNKNOWN %d, TOTAL %d\n\n",
			imageCVESummary.CriticalCount, imageCVESummary.HighCount, imageCVESummary.MediumCount,
			imageCVESummary.LowCount, imageCVESummary.UnknownCount, imageCVESummary.Count)

		fmt.Fprint(config.ResultWriter, statsStr)

		printCVETableHeader(&builder)
		fmt.Fprint(config.ResultWriter, builder.String())
	}

	out, err := result.string(config.OutputFormat, config.Verbose)
	if err != nil {
		return err
	}

	fmt.Fprint(config.ResultWriter, out)

	return nil
}

func SearchImagesByCVEIDGQL(config SearchConfig, repo, cveid string) error {
	username, password := getUsernameAndPassword(config.User)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	var imageList *zcommon.ImagesForCve

	err := zcommon.RetryWithContext(ctx, func(attempt int, retryIn time.Duration) error {
		var err error

		imageList, err = config.SearchService.getTagsForCVEGQL(ctx, config, username, password,
			repo, cveid)
		if err != nil {
			if !strings.Contains(err.Error(), zerr.ErrCVEDBNotFound.Error()) {
				cancel()

				return err
			}

			fmt.Fprintf(config.ResultWriter,
				"[warning] CVE DB is not ready [%d] - retry in %d seconds\n", attempt, int(retryIn.Seconds()))
		}

		return err
	}, maxRetries, CveDBRetryInterval*time.Second)
	if err != nil {
		return err
	}

	imageListData := []imageStruct{}

	for _, image := range imageList.Results {
		imageListData = append(imageListData, imageStruct(image))
	}

	return printImageResult(config, imageListData)
}

func SearchFixedTagsGQL(config SearchConfig, repo, cveid string) error {
	username, password := getUsernameAndPassword(config.User)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	var fixedTags *zcommon.ImageListWithCVEFixedResponse

	err := zcommon.RetryWithContext(ctx, func(attempt int, retryIn time.Duration) error {
		var err error

		fixedTags, err = config.SearchService.getFixedTagsForCVEGQL(ctx, config, username, password,
			repo, cveid)
		if err != nil {
			if !strings.Contains(err.Error(), zerr.ErrCVEDBNotFound.Error()) {
				cancel()

				return err
			}

			fmt.Fprintf(config.ResultWriter,
				"[warning] CVE DB is not ready [%d] - retry in %d seconds\n", attempt, int(retryIn.Seconds()))
		}

		return err
	}, maxRetries, CveDBRetryInterval*time.Second)
	if err != nil {
		return err
	}

	imageList := make([]imageStruct, 0, len(fixedTags.Results))

	for _, image := range fixedTags.Results {
		imageList = append(imageList, imageStruct(image))
	}

	return printImageResult(config, imageList)
}

func GlobalSearchGQL(config SearchConfig, query string) error {
	username, password := getUsernameAndPassword(config.User)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	globalSearchResult, err := config.SearchService.globalSearchGQL(ctx, config, username, password, query)
	if err != nil {
		return err
	}

	imagesList := []imageStruct{}

	for _, image := range globalSearchResult.Images {
		imagesList = append(imagesList, imageStruct(image))
	}

	reposList := []repoStruct{}

	for _, repo := range globalSearchResult.Repos {
		reposList = append(reposList, repoStruct(repo))
	}

	if err := printImageResult(config, imagesList); err != nil {
		return err
	}

	return printRepoResults(config, reposList)
}

func SearchReferrersGQL(config SearchConfig, subject string) error {
	username, password := getUsernameAndPassword(config.User)

	repo, ref, refIsTag, err := zcommon.GetRepoReference(subject)
	if err != nil {
		return err
	}

	digest := ref

	if refIsTag {
		digest, err = fetchImageDigest(repo, ref, username, password, config)
		if err != nil {
			return err
		}
	}

	response, err := config.SearchService.getReferrersGQL(context.Background(), config, username, password, repo, digest)
	if err != nil {
		return err
	}

	referrersList := referrersResult(response.Referrers)

	maxArtifactTypeLen := math.MinInt

	for _, referrer := range referrersList {
		if maxArtifactTypeLen < len(referrer.ArtifactType) {
			maxArtifactTypeLen = len(referrer.ArtifactType)
		}
	}

	printReferrersTableHeader(config, config.ResultWriter, maxArtifactTypeLen)

	return printReferrersResult(config, referrersList, maxArtifactTypeLen)
}

func SearchReferrers(config SearchConfig, subject string) error {
	username, password := getUsernameAndPassword(config.User)

	repo, ref, refIsTag, err := zcommon.GetRepoReference(subject)
	if err != nil {
		return err
	}

	digest := ref

	if refIsTag {
		digest, err = fetchImageDigest(repo, ref, username, password, config)
		if err != nil {
			return err
		}
	}

	referrersList, err := config.SearchService.getReferrers(context.Background(), config, username, password,
		repo, digest)
	if err != nil {
		return err
	}

	maxArtifactTypeLen := math.MinInt

	for _, referrer := range referrersList {
		if maxArtifactTypeLen < len(referrer.ArtifactType) {
			maxArtifactTypeLen = len(referrer.ArtifactType)
		}
	}

	printReferrersTableHeader(config, config.ResultWriter, maxArtifactTypeLen)

	return printReferrersResult(config, referrersList, maxArtifactTypeLen)
}

func SearchRepos(config SearchConfig) error {
	username, password := getUsernameAndPassword(config.User)
	repoErr := make(chan stringResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.SearchService.getRepos(ctx, config, username, password, repoErr, &wg)
	wg.Add(1)

	errCh := make(chan error, 1)

	go collectResults(config, &wg, repoErr, cancel, printImageTableHeader, errCh)
	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}
