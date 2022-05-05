//go:build ui_base || extended || search
// +build ui_base extended search

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	zotErrors "zotregistry.io/zot/errors"
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

type cveByImageSearcher struct{}

func (search cveByImageSearcher) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("imageName")) || *config.fixedFlag {
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

	go config.searchService.getCveByImage(ctx, config, username, password, *config.params["imageName"], strErr, &wg)
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

type imagesByCVEIDSearcher struct{}

func (search imagesByCVEIDSearcher) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("cvid")) || *config.fixedFlag {
		return false, nil
	}

	username, password := getUsernameAndPassword(*config.user)
	strErr := make(chan stringResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.searchService.getImagesByCveID(ctx, config, username, password, *config.params["cvid"], strErr, &wg)
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

type tagsByImageNameAndCVEIDSearcher struct{}

func (search tagsByImageNameAndCVEIDSearcher) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("cvid", "imageName")) || *config.fixedFlag {
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
		*config.params["cvid"], strErr, &wg)
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

type fixedTagsSearcher struct{}

func (search fixedTagsSearcher) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("cvid", "imageName")) || !*config.fixedFlag {
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
		*config.params["cvid"], strErr, &wg)
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

			if !foundResult && (*config.outputFormat == defaultOutoutFormat || *config.outputFormat == "") {
				var builder strings.Builder

				printHeader(&builder, *config.verbose)
				fmt.Fprint(config.resultWriter, builder.String())
			}

			foundResult = true

			fmt.Fprint(config.resultWriter, result.StrValue)
		case <-time.After(waitTimeout):
			config.spinner.stopSpinner()
			cancel()

			errCh <- zotErrors.ErrCLITimeout

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
	ret := &set{}
	ret.m = make(map[string]struct{})

	for _, val := range initialValues {
		ret.m[val] = getEmptyStruct()
	}

	return ret
}

func (s *set) contains(value string) bool {
	_, c := s.m[value]

	return c
}

var (
	ErrCannotSearch        = errors.New("cannot search with these parameters")
	ErrInvalidOutputFormat = errors.New("invalid output format")
)

type stringResult struct {
	StrValue string
	Err      error
}

type printHeader func(writer io.Writer, verbose bool)

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

	row := make([]string, 6) //nolint:gomnd

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

func printCVETableHeader(writer io.Writer, verbose bool) {
	table := getCVETableWriter(writer)
	row := make([]string, 3) //nolint:gomnd
	row[colCVEIDIndex] = "ID"
	row[colCVESeverityIndex] = "SEVERITY"
	row[colCVETitleIndex] = "TITLE"

	table.Append(row)
	table.Render()
}

const (
	waitTimeout = httpTimeout + 5*time.Second
)

var (
	errInvalidImageNameAndTag = errors.New("cli: Invalid input format. Expected IMAGENAME:TAG")
	errInvalidImageName       = errors.New("cli: Invalid input format. Expected IMAGENAME without :TAG")
)
