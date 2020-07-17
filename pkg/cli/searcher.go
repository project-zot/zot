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
	searchService ImageSearchService
	servURL       *string
	user          *string
	outputFormat  *string
	verifyTLS     *bool
	resultWriter  io.Writer
	spinner       spinnerState
}

type allImagesSearcher struct{}

func (search allImagesSearcher) search(config searchConfig) (bool, error) {
	if !canSearch(config.params, newSet("")) {
		return false, nil
	}

	username, password := getUsernameAndPassword(*config.user)
	imageErr := make(chan imageListResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.searchService.getAllImages(ctx, config, username, password, imageErr, &wg)
	wg.Add(1)

	var errCh chan error = make(chan error, 1)

	go collectImages(config, &wg, imageErr, cancel, errCh)
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
	imageErr := make(chan imageListResult)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	wg.Add(1)

	go config.searchService.getImageByName(ctx, config, username, password, *config.params["imageName"], imageErr, &wg)
	wg.Add(1)

	var errCh chan error = make(chan error, 1)
	go collectImages(config, &wg, imageErr, cancel, errCh)

	wg.Wait()

	select {
	case err := <-errCh:
		return true, err
	default:
		return true, nil
	}
}

func collectImages(config searchConfig, wg *sync.WaitGroup, imageErr chan imageListResult,
	cancel context.CancelFunc, errCh chan error) {
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

			if !foundResult && (*config.outputFormat == "text" || *config.outputFormat == "") {
				var builder strings.Builder

				printImageTableHeader(&builder)
				fmt.Fprint(config.resultWriter, builder.String())
			}

			foundResult = true

			fmt.Fprint(config.resultWriter, result.StrValue)
		case <-time.After(waitTimeout):
			cancel()
			config.spinner.stopSpinner()

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
	waitTimeout = 6 * time.Second
)
