// +build extended

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/briandowns/spinner"
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
	resultWriter  io.Writer
	spinner       spinnerState
}

type allImagesSearcher struct{}

func (search allImagesSearcher) search(config searchConfig) (bool, error) {
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

	err := getImages(config)

	return true, err
}

func getImages(config searchConfig) error {
	var builder strings.Builder

	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	imageList, err := config.searchService.getImages(ctx, config, username, password, *config.params["imageName"])

	if err != nil {
		return err
	}

	if len(imageList.Data.ImageList) > 0 && (*config.outputFormat == defaultOutoutFormat || *config.outputFormat == "") {
		printImageTableHeader(&builder, *config.verbose)
		fmt.Fprint(config.resultWriter, builder.String())
	}

	for i := range imageList.Data.ImageList {
		img := imageList.Data.ImageList[i]
		img.verbose = *config.verbose
		out, err := img.string(*config.outputFormat)

		if err != nil {
			return err
		}

		fmt.Fprint(config.resultWriter, out)
	}

	return nil
}

type imagesByDigestSearcher struct{}

func (search imagesByDigestSearcher) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("digest")) {
		return false, nil
	}

	var builder strings.Builder

	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	imageList, err := config.searchService.getImagesByDigest(ctx, config, username, password, *config.params["digest"])

	if err != nil {
		return true, err
	}

	if len(imageList.Data.ImageList) > 0 && (*config.outputFormat == defaultOutoutFormat || *config.outputFormat == "") {
		printImageTableHeader(&builder, *config.verbose)
		fmt.Fprint(config.resultWriter, builder.String())
	}

	for i := range imageList.Data.ImageList {
		img := imageList.Data.ImageList[i]
		img.verbose = *config.verbose
		out, err := img.string(*config.outputFormat)

		if err != nil {
			return true, err
		}

		fmt.Fprint(config.resultWriter, out)
	}

	return true, nil
}

type cveByImageSearcher struct{}

func (search cveByImageSearcher) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("imageName")) || *config.fixedFlag {
		return false, nil
	}

	if !validateImageNameTag(*config.params["imageName"]) {
		return true, errInvalidImageNameAndTag
	}

	var builder strings.Builder

	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	cveList, err := config.searchService.getCveByImage(ctx, config, username, password, *config.params["imageName"])

	if err != nil {
		return true, err
	}

	if len(cveList.Data.CVEListForImage.CVEList) > 0 &&
		(*config.outputFormat == defaultOutoutFormat || *config.outputFormat == "") {
		printCVETableHeader(&builder)
		fmt.Fprint(config.resultWriter, builder.String())
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

	var builder strings.Builder

	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	imageList, err := config.searchService.getImagesByCveID(ctx, config, username, password, *config.params["cveID"])

	if err != nil {
		return true, err
	}

	if len(imageList.Data.ImageListForCVE) > 0 {
		printImageTableHeader(&builder, *config.verbose)
		fmt.Fprint(config.resultWriter, builder.String())
	}

	for i := range imageList.Data.ImageListForCVE {
		img := imageList.Data.ImageListForCVE[i]
		out, err := img.string(*config.outputFormat)

		if err != nil {
			return true, err
		}

		fmt.Fprint(config.resultWriter, out)
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

	err := getTagsByCVE(config)

	return true, err
}

type fixedTagsSearcher struct{}

func (search fixedTagsSearcher) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("cveID", "imageName")) || !*config.fixedFlag {
		return false, nil
	}

	err := getTagsByCVE(config)

	return true, err
}

func getTagsByCVE(config searchConfig) error {
	if strings.Contains(*config.params["imageName"], ":") {
		return errInvalidImageName
	}

	var builder strings.Builder

	username, password := getUsernameAndPassword(*config.user)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	tagList, err := config.searchService.getTagsForCVE(ctx, config, username, password,
		*config.params["imageName"], *config.params["cveID"], *config.fixedFlag)

	if err != nil {
		return err
	}

	if len(tagList.Data.TagListForCve) > 0 {
		printImageTableHeader(&builder, *config.verbose)
		fmt.Fprint(config.resultWriter, builder.String())
	}

	for i := range tagList.Data.TagListForCve {
		img := tagList.Data.TagListForCve[i]
		out, err := img.string(*config.outputFormat)

		if err != nil {
			return err
		}

		fmt.Fprint(config.resultWriter, out)
	}

	return nil
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

//nolint
func (spinner *spinnerState) startSpinner() {
	if spinner.enabled {
		spinner.spinner.Start()
	}
}

//nolint
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
	s := &set{}
	s.m = make(map[string]struct{})

	for _, val := range initialValues {
		s.m[val] = getEmptyStruct()
	}

	return s
}

func (s *set) contains(value string) bool {
	_, c := s.m[value]
	return c
}

var (
	ErrCannotSearch        = errors.New("cannot search with these parameters")
	ErrInvalidOutputFormat = errors.New("invalid output format")
)

func printImageTableHeader(writer io.Writer, verbose bool) {
	table := getImageTableWriter(writer)

	table.SetColMinWidth(colImageNameIndex, imageNameWidth)
	table.SetColMinWidth(colTagIndex, tagWidth)
	table.SetColMinWidth(colDigestIndex, digestWidth)
	table.SetColMinWidth(colSizeIndex, sizeWidth)

	if verbose {
		table.SetColMinWidth(colConfigIndex, configWidth)
		table.SetColMinWidth(colLayersIndex, layersWidth)
	}

	row := make([]string, 6)

	row[colImageNameIndex] = "IMAGE NAME"
	row[colTagIndex] = "TAG"
	row[colDigestIndex] = "DIGEST"
	row[colSizeIndex] = "SIZE"

	if verbose {
		row[colConfigIndex] = "CONFIG"
		row[colLayersIndex] = "LAYERS"
	}

	table.Append(row)
	table.Render()
}

func printCVETableHeader(writer io.Writer) {
	table := getCVETableWriter(writer)
	row := make([]string, 3)
	row[colCVEIDIndex] = "ID"
	row[colCVESeverityIndex] = "SEVERITY"
	row[colCVETitleIndex] = "TITLE"

	table.Append(row)
	table.Render()
}

var (
	errInvalidImageNameAndTag = errors.New("cli: Invalid input format. Expected IMAGENAME:TAG")
	errInvalidImageName       = errors.New("cli: Invalid input format. Expected IMAGENAME without :TAG")
)
