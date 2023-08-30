//go:build search
// +build search

package cli

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	zerr "zotregistry.io/zot/errors"
	zcommon "zotregistry.io/zot/pkg/common"
)

func SearchAllImages(config searchConfig) error {
	username, password := getUsernameAndPassword(*config.user)
	imageErr := make(chan stringResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.searchService.getAllImages(ctx, config, username, password, imageErr, &wg)
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

func SearchAllImagesGQL(config searchConfig) error {
	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	imageList, err := config.searchService.getImagesGQL(ctx, config, username, password, "")
	if err != nil {
		return err
	}

	imageListData := []imageStruct{}

	for _, image := range imageList.Results {
		imageListData = append(imageListData, imageStruct(image))
	}

	return printImageResult(config, imageListData)
}

func SearchImageByName(config searchConfig, image string) error {
	username, password := getUsernameAndPassword(*config.user)
	imageErr := make(chan stringResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.searchService.getImageByName(ctx, config, username, password,
		image, imageErr, &wg)
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

func SearchImageByNameGQL(config searchConfig, imageName string) error {
	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	repo, tag := zcommon.GetImageDirAndTag(imageName)

	imageList, err := config.searchService.getImagesGQL(ctx, config, username, password, repo)
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

func SearchImagesByDigest(config searchConfig, digest string) error {
	username, password := getUsernameAndPassword(*config.user)
	imageErr := make(chan stringResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.searchService.getImagesByDigest(ctx, config, username, password,
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

func SearchDerivedImageListGQL(config searchConfig, derivedImage string) error {
	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	imageList, err := config.searchService.getDerivedImageListGQL(ctx, config, username,
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

func SearchBaseImageListGQL(config searchConfig, baseImage string) error {
	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	imageList, err := config.searchService.getBaseImageListGQL(ctx, config, username,
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

func SearchImagesForDigestGQL(config searchConfig, digest string) error {
	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	imageList, err := config.searchService.getImagesForDigestGQL(ctx, config, username, password, digest)
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

func SearchCVEForImageGQL(config searchConfig, image, searchedCveID string) error {
	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	var cveList *cveResult

	err := zcommon.RetryWithContext(ctx, func(attempt int, retryIn time.Duration) error {
		var err error

		cveList, err = config.searchService.getCveByImageGQL(ctx, config, username, password, image, searchedCveID)
		if err != nil {
			if !strings.Contains(err.Error(), zerr.ErrCVEDBNotFound.Error()) {
				cancel()

				return err
			}

			fmt.Fprintf(config.resultWriter,
				"[warning] CVE DB is not ready [%d] - retry in %d seconds\n", attempt, int(retryIn.Seconds()))
		}

		return err
	}, maxRetries, cveDBRetryInterval*time.Second)
	if err != nil {
		return err
	}

	if len(cveList.Data.CVEListForImage.CVEList) == 0 {
		fmt.Fprint(config.resultWriter, "No CVEs found for image\n")

		return nil
	}

	var builder strings.Builder

	if *config.outputFormat == defaultOutputFormat || *config.outputFormat == "" {
		printCVETableHeader(&builder, *config.verbose, 0, 0, 0)
		fmt.Fprint(config.resultWriter, builder.String())
	}

	out, err := cveList.string(*config.outputFormat)
	if err != nil {
		return err
	}

	fmt.Fprint(config.resultWriter, out)

	return nil
}

func SearchImagesByCVEIDGQL(config searchConfig, repo, cveid string) error {
	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	var imageList *zcommon.ImagesForCve

	err := zcommon.RetryWithContext(ctx, func(attempt int, retryIn time.Duration) error {
		var err error

		imageList, err = config.searchService.getTagsForCVEGQL(ctx, config, username, password,
			repo, cveid)
		if err != nil {
			if !strings.Contains(err.Error(), zerr.ErrCVEDBNotFound.Error()) {
				cancel()

				return err
			}

			fmt.Fprintf(config.resultWriter,
				"[warning] CVE DB is not ready [%d] - retry in %d seconds\n", attempt, int(retryIn.Seconds()))
		}

		return err
	}, maxRetries, cveDBRetryInterval*time.Second)
	if err != nil {
		return err
	}

	imageListData := []imageStruct{}

	for _, image := range imageList.Results {
		imageListData = append(imageListData, imageStruct(image))
	}

	return printImageResult(config, imageListData)
}

func SearchFixedTagsGQL(config searchConfig, repo, cveid string) error {
	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	var fixedTags *zcommon.ImageListWithCVEFixedResponse

	err := zcommon.RetryWithContext(ctx, func(attempt int, retryIn time.Duration) error {
		var err error

		fixedTags, err = config.searchService.getFixedTagsForCVEGQL(ctx, config, username, password,
			repo, cveid)
		if err != nil {
			if !strings.Contains(err.Error(), zerr.ErrCVEDBNotFound.Error()) {
				cancel()

				return err
			}

			fmt.Fprintf(config.resultWriter,
				"[warning] CVE DB is not ready [%d] - retry in %d seconds\n", attempt, int(retryIn.Seconds()))
		}

		return err
	}, maxRetries, cveDBRetryInterval*time.Second)
	if err != nil {
		return err
	}

	imageList := make([]imageStruct, 0, len(fixedTags.Results))

	for _, image := range fixedTags.Results {
		imageList = append(imageList, imageStruct(image))
	}

	return printImageResult(config, imageList)
}

func GlobalSearchGQL(config searchConfig, query string) error {
	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	globalSearchResult, err := config.searchService.globalSearchGQL(ctx, config, username, password, query)
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

func SearchReferrersGQL(config searchConfig, subject string) error {
	username, password := getUsernameAndPassword(*config.user)

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

	response, err := config.searchService.getReferrersGQL(context.Background(), config, username, password, repo, digest)
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

	printReferrersTableHeader(config, config.resultWriter, maxArtifactTypeLen)

	return printReferrersResult(config, referrersList, maxArtifactTypeLen)
}

func SearchReferrers(config searchConfig, subject string) error {
	username, password := getUsernameAndPassword(*config.user)

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

	referrersList, err := config.searchService.getReferrers(context.Background(), config, username, password,
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

	printReferrersTableHeader(config, config.resultWriter, maxArtifactTypeLen)

	return printReferrersResult(config, referrersList, maxArtifactTypeLen)
}

func SearchRepos(config searchConfig) error {
	username, password := getUsernameAndPassword(*config.user)
	repoErr := make(chan stringResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.searchService.getRepos(ctx, config, username, password, repoErr, &wg)
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
