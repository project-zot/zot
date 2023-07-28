//go:build search
// +build search

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/constants"
	zcommon "zotregistry.io/zot/pkg/common"
)

func getImageSearchers() []searcher {
	searchers := []searcher{
		new(allImagesSearcher),
		new(imageByNameSearcher),
		new(imagesByDigestSearcher),
	}

	return searchers
}

func getCveSearchers() []searcher {
	searchers := []searcher{
		new(cveByImageSearcher),
		new(imagesByCVEIDSearcher),
		new(tagsByImageNameAndCVEIDSearcher),
		new(fixedTagsSearcher),
	}

	return searchers
}

func getImageSearchersGQL() []searcher {
	searchers := []searcher{
		new(allImagesSearcherGQL),
		new(imageByNameSearcherGQL),
		new(imagesByDigestSearcherGQL),
		new(derivedImageListSearcherGQL),
		new(baseImageListSearcherGQL),
	}

	return searchers
}

func getCveSearchersGQL() []searcher {
	searchers := []searcher{
		new(cveByImageSearcherGQL),
		new(imagesByCVEIDSearcherGQL),
		new(tagsByImageNameAndCVEIDSearcherGQL),
		new(fixedTagsSearcherGQL),
	}

	return searchers
}

func getGlobalSearchersGQL() []searcher {
	searchers := []searcher{
		new(globalSearcherGQL),
		new(referrerSearcherGQL),
	}

	return searchers
}

func getGlobalSearchersREST() []searcher {
	searchers := []searcher{
		new(referrerSearcher),
		new(globalSearcherREST),
	}

	return searchers
}

type searcher interface {
	search(searchConfig searchConfig) (bool, error)
}

func canSearch(params map[string]*string, requiredParams *set) bool {
	for key, value := range params {
		if requiredParams.contains(key) && *value == "" {
			return false
		} else if !requiredParams.contains(key) && *value != "" {
			return false
		}
	}

	return true
}

type searchConfig struct {
	params        map[string]*string
	searchService SearchService
	servURL       *string
	user          *string
	outputFormat  *string
	verifyTLS     *bool
	fixedFlag     *bool
	verbose       *bool
	debug         *bool
	resultWriter  io.Writer
	spinner       spinnerState
}

type allImagesSearcher struct{}

func (search allImagesSearcher) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("")) {
		return false, nil
	}

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
		return true, err
	default:
		return true, nil
	}
}

type allImagesSearcherGQL struct{}

func (search allImagesSearcherGQL) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("")) {
		return false, nil
	}

	err := getImages(config)

	return true, err
}

type imageByNameSearcher struct{}

func (search imageByNameSearcher) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("imageName")) {
		return false, nil
	}

	username, password := getUsernameAndPassword(*config.user)
	imageErr := make(chan stringResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.searchService.getImageByName(ctx, config, username, password,
		*config.params["imageName"], imageErr, &wg)
	wg.Add(1)

	errCh := make(chan error, 1)
	go collectResults(config, &wg, imageErr, cancel, printImageTableHeader, errCh)

	wg.Wait()

	select {
	case err := <-errCh:
		return true, err
	default:
		return true, nil
	}
}

type imageByNameSearcherGQL struct{}

func (search imageByNameSearcherGQL) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("imageName")) {
		return false, nil
	}

	err := getImages(config)

	return true, err
}

func getImages(config searchConfig) error {
	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	imageList, err := config.searchService.getImagesGQL(ctx, config, username, password, *config.params["imageName"])
	if err != nil {
		return err
	}

	imageListData := []imageStruct{}

	for _, image := range imageList.Results {
		imageListData = append(imageListData, imageStruct(image))
	}

	return printImageResult(config, imageListData)
}

type imagesByDigestSearcher struct{}

func (search imagesByDigestSearcher) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("digest")) {
		return false, nil
	}

	username, password := getUsernameAndPassword(*config.user)
	imageErr := make(chan stringResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.searchService.getImagesByDigest(ctx, config, username, password,
		*config.params["digest"], imageErr, &wg)
	wg.Add(1)

	errCh := make(chan error, 1)
	go collectResults(config, &wg, imageErr, cancel, printImageTableHeader, errCh)

	wg.Wait()

	select {
	case err := <-errCh:
		return true, err
	default:
		return true, nil
	}
}

type derivedImageListSearcherGQL struct{}

func (search derivedImageListSearcherGQL) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("derivedImage")) {
		return false, nil
	}

	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	imageList, err := config.searchService.getDerivedImageListGQL(ctx, config, username,
		password, *config.params["derivedImage"])
	if err != nil {
		return true, err
	}

	imageListData := []imageStruct{}

	for _, image := range imageList.DerivedImageList.Results {
		imageListData = append(imageListData, imageStruct(image))
	}

	if err := printImageResult(config, imageListData); err != nil {
		return true, err
	}

	return true, nil
}

type baseImageListSearcherGQL struct{}

func (search baseImageListSearcherGQL) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("baseImage")) {
		return false, nil
	}

	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	imageList, err := config.searchService.getBaseImageListGQL(ctx, config, username,
		password, *config.params["baseImage"])
	if err != nil {
		return true, err
	}

	imageListData := []imageStruct{}

	for _, image := range imageList.BaseImageList.Results {
		imageListData = append(imageListData, imageStruct(image))
	}

	if err := printImageResult(config, imageListData); err != nil {
		return true, err
	}

	return true, nil
}

type imagesByDigestSearcherGQL struct{}

func (search imagesByDigestSearcherGQL) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("digest")) {
		return false, nil
	}

	// var builder strings.Builder

	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	imageList, err := config.searchService.getImagesForDigestGQL(ctx, config, username, password, *config.params["digest"])
	if err != nil {
		return true, err
	}

	imageListData := []imageStruct{}

	for _, image := range imageList.Results {
		imageListData = append(imageListData, imageStruct(image))
	}

	if err := printImageResult(config, imageListData); err != nil {
		return true, err
	}

	return true, nil
}

type cveByImageSearcher struct{}

func (search cveByImageSearcher) search(config searchConfig) (bool, error) {
	if (!canSearch(config.params, newSet("imageName")) &&
		!canSearch(config.params, newSet("imageName", "searchedCVE"))) || *config.fixedFlag {
		return false, nil
	}

	if !validateImageNameTag(*config.params["imageName"]) {
		return true, errInvalidImageNameAndTag
	}

	username, password := getUsernameAndPassword(*config.user)
	strErr := make(chan stringResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.searchService.getCveByImage(ctx, config, username, password, *config.params["imageName"],
		*config.params["searchedCVE"], strErr, &wg)
	wg.Add(1)

	errCh := make(chan error, 1)
	go collectResults(config, &wg, strErr, cancel, printCVETableHeader, errCh)

	wg.Wait()

	select {
	case err := <-errCh:
		return true, err
	default:
		return true, nil
	}
}

type cveByImageSearcherGQL struct{}

func (search cveByImageSearcherGQL) search(config searchConfig) (bool, error) {
	if (!canSearch(config.params, newSet("imageName")) &&
		!canSearch(config.params, newSet("imageName", "searchedCVE"))) || *config.fixedFlag {
		return false, nil
	}

	if !validateImageNameTag(*config.params["imageName"]) {
		return true, errInvalidImageNameAndTag
	}

	var builder strings.Builder

	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	cveList, err := config.searchService.getCveByImageGQL(ctx, config, username, password,
		*config.params["imageName"], *config.params["searchedCVE"])
	if err != nil {
		return true, err
	}

	if len(cveList.Data.CVEListForImage.CVEList) > 0 &&
		(*config.outputFormat == defaultOutputFormat || *config.outputFormat == "") {
		printCVETableHeader(&builder, *config.verbose, 0, 0, 0)
		fmt.Fprint(config.resultWriter, builder.String())
	}

	if len(cveList.Data.CVEListForImage.CVEList) == 0 {
		fmt.Fprint(config.resultWriter, "No CVEs found for image\n")

		return true, nil
	}

	out, err := cveList.string(*config.outputFormat)
	if err != nil {
		return true, err
	}

	fmt.Fprint(config.resultWriter, out)

	return true, nil
}

type imagesByCVEIDSearcher struct{}

func (search imagesByCVEIDSearcher) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("cveID")) || *config.fixedFlag {
		return false, nil
	}

	username, password := getUsernameAndPassword(*config.user)
	strErr := make(chan stringResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.searchService.getImagesByCveID(ctx, config, username, password, *config.params["cveID"], strErr, &wg)
	wg.Add(1)

	errCh := make(chan error, 1)
	go collectResults(config, &wg, strErr, cancel, printImageTableHeader, errCh)

	wg.Wait()

	select {
	case err := <-errCh:
		return true, err
	default:
		return true, nil
	}
}

type imagesByCVEIDSearcherGQL struct{}

func (search imagesByCVEIDSearcherGQL) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("cveID")) || *config.fixedFlag {
		return false, nil
	}

	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	imageList, err := config.searchService.getImagesByCveIDGQL(ctx, config, username, password, *config.params["cveID"])
	if err != nil {
		return true, err
	}

	imageListData := []imageStruct{}

	for _, image := range imageList.Results {
		imageListData = append(imageListData, imageStruct(image))
	}

	if err := printImageResult(config, imageListData); err != nil {
		return true, err
	}

	return true, nil
}

type tagsByImageNameAndCVEIDSearcher struct{}

func (search tagsByImageNameAndCVEIDSearcher) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("cveID", "imageName")) || *config.fixedFlag {
		return false, nil
	}

	if strings.Contains(*config.params["imageName"], ":") {
		return true, errInvalidImageName
	}

	username, password := getUsernameAndPassword(*config.user)
	strErr := make(chan stringResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.searchService.getImageByNameAndCVEID(ctx, config, username, password, *config.params["imageName"],
		*config.params["cveID"], strErr, &wg)
	wg.Add(1)

	errCh := make(chan error, 1)
	go collectResults(config, &wg, strErr, cancel, printImageTableHeader, errCh)

	wg.Wait()

	select {
	case err := <-errCh:
		return true, err
	default:
		return true, nil
	}
}

type tagsByImageNameAndCVEIDSearcherGQL struct{}

func (search tagsByImageNameAndCVEIDSearcherGQL) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("cveID", "imageName")) || *config.fixedFlag {
		return false, nil
	}

	if strings.Contains(*config.params["imageName"], ":") {
		return true, errInvalidImageName
	}

	err := getTagsByCVE(config)

	return true, err
}

type fixedTagsSearcherGQL struct{}

func (search fixedTagsSearcherGQL) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("cveID", "imageName")) || !*config.fixedFlag {
		return false, nil
	}

	err := getTagsByCVE(config)

	return true, err
}

type fixedTagsSearcher struct{}

func (search fixedTagsSearcher) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("cveID", "imageName")) || !*config.fixedFlag {
		return false, nil
	}

	if strings.Contains(*config.params["imageName"], ":") {
		return true, errInvalidImageName
	}

	username, password := getUsernameAndPassword(*config.user)
	strErr := make(chan stringResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.searchService.getFixedTagsForCVE(ctx, config, username, password, *config.params["imageName"],
		*config.params["cveID"], strErr, &wg)
	wg.Add(1)

	errCh := make(chan error, 1)
	go collectResults(config, &wg, strErr, cancel, printImageTableHeader, errCh)

	wg.Wait()

	select {
	case err := <-errCh:
		return true, err
	default:
		return true, nil
	}
}

func getTagsByCVE(config searchConfig) error {
	if strings.Contains(*config.params["imageName"], ":") {
		return errInvalidImageName
	}

	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	var imageList []imageStruct

	if *config.fixedFlag {
		fixedTags, err := config.searchService.getFixedTagsForCVEGQL(ctx, config, username, password,
			*config.params["imageName"], *config.params["cveID"])
		if err != nil {
			return err
		}

		for _, image := range fixedTags.Results {
			imageList = append(imageList, imageStruct(image))
		}
	} else {
		tags, err := config.searchService.getTagsForCVEGQL(ctx, config, username, password,
			*config.params["imageName"], *config.params["cveID"])
		if err != nil {
			return err
		}

		imageList = nil
		for _, image := range tags.Results {
			imageList = append(imageList, imageStruct(image))
		}
	}

	return printImageResult(config, imageList)
}

type referrerSearcherGQL struct{}

func (search referrerSearcherGQL) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("subject")) {
		return false, nil
	}

	username, password := getUsernameAndPassword(*config.user)

	repo, ref, refIsTag, err := zcommon.GetRepoReference(*config.params["subject"])
	if err != nil {
		return true, err
	}

	digest := ref

	if refIsTag {
		digest, err = fetchImageDigest(repo, ref, username, password, config)
		if err != nil {
			return true, err
		}
	}

	response, err := config.searchService.getReferrersGQL(context.Background(), config, username, password, repo, digest)
	if err != nil {
		return true, err
	}

	referrersList := referrersResult(response.Referrers)

	maxArtifactTypeLen := math.MinInt

	for _, referrer := range referrersList {
		if maxArtifactTypeLen < len(referrer.ArtifactType) {
			maxArtifactTypeLen = len(referrer.ArtifactType)
		}
	}

	printReferrersTableHeader(config, config.resultWriter, maxArtifactTypeLen)

	return true, printReferrersResult(config, referrersList, maxArtifactTypeLen)
}

func fetchImageDigest(repo, ref, username, password string, config searchConfig) (string, error) {
	url, err := combineServerAndEndpointURL(*config.servURL, fmt.Sprintf("/v2/%s/manifests/%s", repo, ref))
	if err != nil {
		return "", err
	}

	res, err := makeHEADRequest(context.Background(), url, username, password, *config.verifyTLS, false)

	digestStr := res.Get(constants.DistContentDigestKey)

	return digestStr, err
}

type referrerSearcher struct{}

func (search referrerSearcher) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("subject")) {
		return false, nil
	}

	username, password := getUsernameAndPassword(*config.user)

	repo, ref, refIsTag, err := zcommon.GetRepoReference(*config.params["subject"])
	if err != nil {
		return true, err
	}

	digest := ref

	if refIsTag {
		digest, err = fetchImageDigest(repo, ref, username, password, config)
		if err != nil {
			return true, err
		}
	}

	referrersList, err := config.searchService.getReferrers(context.Background(), config, username, password,
		repo, digest)
	if err != nil {
		return true, err
	}

	maxArtifactTypeLen := math.MinInt

	for _, referrer := range referrersList {
		if maxArtifactTypeLen < len(referrer.ArtifactType) {
			maxArtifactTypeLen = len(referrer.ArtifactType)
		}
	}

	printReferrersTableHeader(config, config.resultWriter, maxArtifactTypeLen)

	return true, printReferrersResult(config, referrersList, maxArtifactTypeLen)
}

type globalSearcherGQL struct{}

func (search globalSearcherGQL) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("query")) {
		return false, nil
	}

	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	query := *config.params["query"]

	globalSearchResult, err := config.searchService.globalSearchGQL(ctx, config, username, password, query)
	if err != nil {
		return true, err
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
		return true, err
	}

	return true, printRepoResults(config, reposList)
}

type globalSearcherREST struct{}

func (search globalSearcherREST) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("query")) {
		return false, nil
	}

	return true, fmt.Errorf("search extension is not enabled: %w", zerr.ErrExtensionNotEnabled)
}

func collectResults(config searchConfig, wg *sync.WaitGroup, imageErr chan stringResult,
	cancel context.CancelFunc, printHeader printHeader, errCh chan error,
) {
	var foundResult bool

	defer wg.Done()
	config.spinner.startSpinner()

	for {
		select {
		case result, ok := <-imageErr:
			config.spinner.stopSpinner()

			if !ok {
				cancel()

				return
			}

			if result.Err != nil {
				cancel()
				errCh <- result.Err

				return
			}

			if !foundResult && (*config.outputFormat == defaultOutputFormat || *config.outputFormat == "") {
				var builder strings.Builder

				printHeader(&builder, *config.verbose, 0, 0, 0)
				fmt.Fprint(config.resultWriter, builder.String())
			}

			foundResult = true

			fmt.Fprint(config.resultWriter, result.StrValue)
		case <-time.After(waitTimeout):
			config.spinner.stopSpinner()
			cancel()

			errCh <- zerr.ErrCLITimeout

			return
		}
	}
}

func getUsernameAndPassword(user string) (string, string) {
	if strings.Contains(user, ":") {
		split := strings.Split(user, ":")

		return split[0], split[1]
	}

	return "", ""
}

func validateImageNameTag(input string) bool {
	if !strings.Contains(input, ":") {
		return false
	}

	split := strings.Split(input, ":")
	name := strings.TrimSpace(split[0])
	tag := strings.TrimSpace(split[1])

	if name == "" || tag == "" {
		return false
	}

	return true
}

type spinnerState struct {
	spinner *spinner.Spinner
	enabled bool
}

func (spinner *spinnerState) startSpinner() {
	if spinner.enabled {
		spinner.spinner.Start()
	}
}

func (spinner *spinnerState) stopSpinner() {
	if spinner.enabled && spinner.spinner.Active() {
		spinner.spinner.Stop()
	}
}

type set struct {
	m map[string]struct{}
}

func getEmptyStruct() struct{} {
	return struct{}{}
}

func newSet(initialValues ...string) *set {
	setValues := &set{}
	setValues.m = make(map[string]struct{})

	for _, val := range initialValues {
		setValues.m[val] = getEmptyStruct()
	}

	return setValues
}

func (s *set) contains(value string) bool {
	_, c := s.m[value]

	return c
}

const (
	waitTimeout = httpTimeout + 5*time.Second
)

var (
	ErrCannotSearch        = errors.New("cannot search with these parameters")
	ErrInvalidOutputFormat = errors.New("invalid output format")
)

type stringResult struct {
	StrValue string
	Err      error
}

type printHeader func(writer io.Writer, verbose bool, maxImageNameLen, maxTagLen, maxPlatformLen int)

func printImageTableHeader(writer io.Writer, verbose bool, maxImageNameLen, maxTagLen, maxPlatformLen int) {
	table := getImageTableWriter(writer)

	table.SetColMinWidth(colImageNameIndex, imageNameWidth)
	table.SetColMinWidth(colTagIndex, tagWidth)
	table.SetColMinWidth(colPlatformIndex, platformWidth)
	table.SetColMinWidth(colDigestIndex, digestWidth)
	table.SetColMinWidth(colSizeIndex, sizeWidth)
	table.SetColMinWidth(colIsSignedIndex, isSignedWidth)

	if verbose {
		table.SetColMinWidth(colConfigIndex, configWidth)
		table.SetColMinWidth(colLayersIndex, layersWidth)
	}

	row := make([]string, 8) //nolint:gomnd

	// adding spaces so that repository and tag columns are aligned
	// in case the name/tag are fully shown and too long
	var offset string
	if maxImageNameLen > len("REPOSITORY") {
		offset = strings.Repeat(" ", maxImageNameLen-len("REPOSITORY"))
		row[colImageNameIndex] = "REPOSITORY" + offset
	} else {
		row[colImageNameIndex] = "REPOSITORY"
	}

	if maxTagLen > len("TAG") {
		offset = strings.Repeat(" ", maxTagLen-len("TAG"))
		row[colTagIndex] = "TAG" + offset
	} else {
		row[colTagIndex] = "TAG"
	}

	if maxPlatformLen > len("OS/ARCH") {
		offset = strings.Repeat(" ", maxPlatformLen-len("OS/ARCH"))
		row[colPlatformIndex] = "OS/ARCH" + offset
	} else {
		row[colPlatformIndex] = "OS/ARCH"
	}

	row[colDigestIndex] = "DIGEST"
	row[colSizeIndex] = sizeColumn
	row[colIsSignedIndex] = "SIGNED"

	if verbose {
		row[colConfigIndex] = "CONFIG"
		row[colLayersIndex] = "LAYERS"
	}

	table.Append(row)
	table.Render()
}

func printCVETableHeader(writer io.Writer, verbose bool, maxImgLen, maxTagLen, maxPlatformLen int) {
	table := getCVETableWriter(writer)
	row := make([]string, 3) //nolint:gomnd
	row[colCVEIDIndex] = "ID"
	row[colCVESeverityIndex] = "SEVERITY"
	row[colCVETitleIndex] = "TITLE"

	table.Append(row)
	table.Render()
}

func printReferrersTableHeader(config searchConfig, writer io.Writer, maxArtifactTypeLen int) {
	if *config.outputFormat != "" && *config.outputFormat != defaultOutputFormat {
		return
	}

	table := getReferrersTableWriter(writer)

	table.SetColMinWidth(refArtifactTypeIndex, maxArtifactTypeLen)
	table.SetColMinWidth(refDigestIndex, digestWidth)
	table.SetColMinWidth(refSizeIndex, sizeWidth)

	row := make([]string, refRowWidth)

	// adding spaces so that repository and tag columns are aligned
	// in case the name/tag are fully shown and too long
	var offset string

	if maxArtifactTypeLen > len("ARTIFACT TYPE") {
		offset = strings.Repeat(" ", maxArtifactTypeLen-len("ARTIFACT TYPE"))
		row[refArtifactTypeIndex] = "ARTIFACT TYPE" + offset
	} else {
		row[refArtifactTypeIndex] = "ARTIFACT TYPE"
	}

	row[refDigestIndex] = "DIGEST"
	row[refSizeIndex] = sizeColumn

	table.Append(row)
	table.Render()
}

func printRepoTableHeader(writer io.Writer, repoMaxLen, maxTimeLen int, verbose bool) {
	table := getRepoTableWriter(writer)

	table.SetColMinWidth(repoNameIndex, repoMaxLen)
	table.SetColMinWidth(repoSizeIndex, sizeWidth)
	table.SetColMinWidth(repoLastUpdatedIndex, maxTimeLen)
	table.SetColMinWidth(repoDownloadsIndex, sizeWidth)
	table.SetColMinWidth(repoStarsIndex, sizeWidth)

	if verbose {
		table.SetColMinWidth(repoPlatformsIndex, platformWidth)
	}

	row := make([]string, repoRowWidth)

	// adding spaces so that repository and tag columns are aligned
	// in case the name/tag are fully shown and too long
	var offset string

	if repoMaxLen > len("NAME") {
		offset = strings.Repeat(" ", repoMaxLen-len("NAME"))
		row[repoNameIndex] = "NAME" + offset
	} else {
		row[repoNameIndex] = "NAME"
	}

	if repoMaxLen > len("LAST UPDATED") {
		offset = strings.Repeat(" ", repoMaxLen-len("LAST UPDATED"))
		row[repoLastUpdatedIndex] = "LAST UPDATED" + offset
	} else {
		row[repoLastUpdatedIndex] = "LAST UPDATED"
	}

	row[repoSizeIndex] = sizeColumn
	row[repoDownloadsIndex] = "DOWNLOADS"
	row[repoStarsIndex] = "STARS"

	if verbose {
		row[repoPlatformsIndex] = "PLATFORMS"
	}

	table.Append(row)
	table.Render()
}

func printReferrersResult(config searchConfig, referrersList referrersResult, maxArtifactTypeLen int) error {
	out, err := referrersList.string(*config.outputFormat, maxArtifactTypeLen)
	if err != nil {
		return err
	}

	fmt.Fprint(config.resultWriter, out)

	return nil
}

func printImageResult(config searchConfig, imageList []imageStruct) error {
	var builder strings.Builder
	maxImgNameLen := 0
	maxTagLen := 0
	maxPlatformLen := 0

	if len(imageList) > 0 {
		for i := range imageList {
			if maxImgNameLen < len(imageList[i].RepoName) {
				maxImgNameLen = len(imageList[i].RepoName)
			}

			if maxTagLen < len(imageList[i].Tag) {
				maxTagLen = len(imageList[i].Tag)
			}

			for j := range imageList[i].Manifests {
				platform := imageList[i].Manifests[j].Platform.Os + "/" + imageList[i].Manifests[j].Platform.Arch

				if maxPlatformLen < len(platform) {
					maxPlatformLen = len(platform)
				}
			}
		}

		if *config.outputFormat == defaultOutputFormat || *config.outputFormat == "" {
			printImageTableHeader(&builder, *config.verbose, maxImgNameLen, maxTagLen, maxPlatformLen)
		}

		fmt.Fprint(config.resultWriter, builder.String())
	}

	for i := range imageList {
		img := imageList[i]
		verbose := *config.verbose

		out, err := img.string(*config.outputFormat, maxImgNameLen, maxTagLen, maxPlatformLen, verbose)
		if err != nil {
			return err
		}

		fmt.Fprint(config.resultWriter, out)
	}

	return nil
}

func printRepoResults(config searchConfig, repoList []repoStruct) error {
	maxRepoNameLen := 0
	maxTimeLen := 0

	for _, repo := range repoList {
		if maxRepoNameLen < len(repo.Name) {
			maxRepoNameLen = len(repo.Name)
		}

		if maxTimeLen < len(repo.LastUpdated.String()) {
			maxTimeLen = len(repo.LastUpdated.String())
		}
	}

	if len(repoList) > 0 && (*config.outputFormat == defaultOutputFormat || *config.outputFormat == "") {
		printRepoTableHeader(config.resultWriter, maxRepoNameLen, maxTimeLen, *config.verbose)
	}

	for _, repo := range repoList {
		out, err := repo.string(*config.outputFormat, maxRepoNameLen, maxTimeLen, *config.verbose)
		if err != nil {
			return err
		}

		fmt.Fprint(config.resultWriter, out)
	}

	return nil
}

var (
	errInvalidImageNameAndTag = errors.New("cli: Invalid input format. Expected IMAGENAME:TAG")
	errInvalidImageName       = errors.New("cli: Invalid input format. Expected IMAGENAME without :TAG")
)

type repoSearcher struct{}

func (search repoSearcher) searchRepos(config searchConfig) error {
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

const (
	sizeColumn = "SIZE"
)
