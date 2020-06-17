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
)

func getSearchers() []searcher {
	searchers := []searcher{
		new(allImagesSearcher),
		new(imageByNameSearcher),
	}

	return searchers
}

type searcher interface {
	search(params map[string]*string, searchService ImageSearchService,
		servURL, user, outputFormat *string, stdWriter io.Writer, spinner spinnerState) (bool, error)
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

type allImagesSearcher struct{}

func (search allImagesSearcher) search(params map[string]*string, searchService ImageSearchService,
	servURL, user, outputFormat *string, stdWriter io.Writer, spinner spinnerState) (bool, error) {
	if !canSearch(params, newSet("")) {
		return false, nil
	}

	username, password := getUsernameAndPassword(*user)
	imageErr := make(chan imageListResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go searchService.getAllImages(ctx, *servURL, username, password, *outputFormat, imageErr, &wg)
	wg.Add(1)

	var errCh chan error = make(chan error, 1)

	go collectImages(outputFormat, stdWriter, &wg, imageErr, cancel, spinner, errCh)
	wg.Wait()
	select {
	case err := <-errCh:
		return true, err
	default:
		return true, nil
	}
}

type imageByNameSearcher struct{}

func (search imageByNameSearcher) search(params map[string]*string,
	searchService ImageSearchService, servURL, user, outputFormat *string,
	stdWriter io.Writer, spinner spinnerState) (bool, error) {
	if !canSearch(params, newSet("imageName")) {
		return false, nil
	}

	username, password := getUsernameAndPassword(*user)
	imageErr := make(chan imageListResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go searchService.getImageByName(ctx, *servURL, username, password, *params["imageName"], *outputFormat, imageErr, &wg)
	wg.Add(1)

	var errCh chan error = make(chan error, 1)
	go collectImages(outputFormat, stdWriter, &wg, imageErr, cancel, spinner, errCh)

	wg.Wait()

	select {
	case err := <-errCh:
		return true, err
	default:
		return true, nil
	}
}

func collectImages(outputFormat *string, stdWriter io.Writer, wg *sync.WaitGroup,
	imageErr chan imageListResult, cancel context.CancelFunc, spinner spinnerState, errCh chan error) {
	var foundResult bool

	defer wg.Done()
	spinner.startSpinner()

	for {
		select {
		case result := <-imageErr:
			if result.Err != nil {
				spinner.stopSpinner()
				cancel()
				errCh <- result.Err

				return
			}

			if !foundResult && (*outputFormat == "text" || *outputFormat == "") {
				spinner.stopSpinner()

				var builder strings.Builder

				printImageTableHeader(&builder)
				fmt.Fprint(stdWriter, builder.String())
			}

			foundResult = true

			fmt.Fprint(stdWriter, result.StrValue)
		case <-time.After(waitTimeout):
			cancel()
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

type imageListResult struct {
	StrValue string
	Err      error
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

func printImageTableHeader(writer io.Writer) {
	table := getNoBorderTableWriter(writer)
	row := []string{"IMAGE NAME",
		"TAG",
		"DIGEST",
		"SIZE",
	}
	table.Append(row)
	table.Render()
}

const (
	waitTimeout = 2 * time.Second
)
