//go:build search
// +build search

package client

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/constants"
)

const (
	sizeColumn = "SIZE"
)

func ref[T any](input T) *T {
	ref := input

	return &ref
}

func fetchImageDigest(repo, ref, username, password string, config SearchConfig) (string, error) {
	url, err := combineServerAndEndpointURL(config.ServURL, fmt.Sprintf("/v2/%s/manifests/%s", repo, ref))
	if err != nil {
		return "", err
	}

	res, err := makeHEADRequest(context.Background(), url, username, password, config.VerifyTLS, false)

	digestStr := res.Get(constants.DistContentDigestKey)

	return digestStr, err
}

func collectResults(config SearchConfig, wg *sync.WaitGroup, imageErr chan stringResult,
	cancel context.CancelFunc, printHeader printHeader, errCh chan error,
) {
	var foundResult bool

	defer wg.Done()
	config.Spinner.startSpinner()

	for {
		select {
		case result, ok := <-imageErr:
			config.Spinner.stopSpinner()

			if !ok {
				cancel()

				return
			}

			if result.Err != nil {
				cancel()
				errCh <- result.Err

				return
			}

			if !foundResult && (config.OutputFormat == defaultOutputFormat || config.OutputFormat == "") {
				var builder strings.Builder

				printHeader(&builder, config.Verbose, 0, 0, 0)
				fmt.Fprint(config.ResultWriter, builder.String())
			}

			foundResult = true

			fmt.Fprint(config.ResultWriter, result.StrValue)
		case <-time.After(waitTimeout):
			config.Spinner.stopSpinner()
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

const (
	waitTimeout = 5 * time.Minute
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

func printCVETableHeader(writer io.Writer) {
	table := getCVETableWriter(writer)
	columnHeadingsRow := []string{
		"ID", "SEVERITY", "TITLE",
		"VULNERABLE PACKAGE", "PATH", "INSTALL-VER", "FIXED-VER",
	}

	table.Append(columnHeadingsRow)
	table.Render()
}

func printReferrersTableHeader(config SearchConfig, writer io.Writer, maxArtifactTypeLen int) {
	if config.OutputFormat != "" && config.OutputFormat != defaultOutputFormat {
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

func printReferrersResult(config SearchConfig, referrersList referrersResult, maxArtifactTypeLen int) error {
	out, err := referrersList.string(config.OutputFormat, maxArtifactTypeLen)
	if err != nil {
		return err
	}

	fmt.Fprint(config.ResultWriter, out)

	return nil
}

func printImageResult(config SearchConfig, imageList []imageStruct) error {
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

		if config.OutputFormat == defaultOutputFormat || config.OutputFormat == "" {
			printImageTableHeader(&builder, config.Verbose, maxImgNameLen, maxTagLen, maxPlatformLen)
		}

		fmt.Fprint(config.ResultWriter, builder.String())
	}

	for i := range imageList {
		img := imageList[i]
		verbose := config.Verbose

		out, err := img.string(config.OutputFormat, maxImgNameLen, maxTagLen, maxPlatformLen, verbose)
		if err != nil {
			return err
		}

		fmt.Fprint(config.ResultWriter, out)
	}

	return nil
}

func printRepoResults(config SearchConfig, repoList []repoStruct) error {
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

	if len(repoList) > 0 && (config.OutputFormat == defaultOutputFormat || config.OutputFormat == "") {
		printRepoTableHeader(config.ResultWriter, maxRepoNameLen, maxTimeLen, config.Verbose)
	}

	for _, repo := range repoList {
		out, err := repo.string(config.OutputFormat, maxRepoNameLen, maxTimeLen, config.Verbose)
		if err != nil {
			return err
		}

		fmt.Fprint(config.ResultWriter, out)
	}

	return nil
}

func GetSearchConfigFromFlags(cmd *cobra.Command, searchService SearchService) (SearchConfig, error) {
	serverURL, err := GetServerURLFromFlags(cmd)
	if err != nil {
		return SearchConfig{}, err
	}

	isSpinner, verifyTLS, err := GetCliConfigOptions(cmd)
	if err != nil {
		return SearchConfig{}, err
	}

	flags := cmd.Flags()
	user := defaultIfError(flags.GetString(UserFlag))
	fixed := defaultIfError(flags.GetBool(FixedFlag))
	debug := defaultIfError(flags.GetBool(DebugFlag))
	verbose := defaultIfError(flags.GetBool(VerboseFlag))
	outputFormat := defaultIfError(flags.GetString(OutputFormatFlag))
	sortBy := defaultIfError(flags.GetString(SortByFlag))

	spin := spinner.New(spinner.CharSets[39], spinnerDuration, spinner.WithWriter(cmd.ErrOrStderr()))
	spin.Prefix = prefix

	return SearchConfig{
		SearchService: searchService,
		ServURL:       serverURL,
		User:          user,
		OutputFormat:  outputFormat,
		VerifyTLS:     verifyTLS,
		FixedFlag:     fixed,
		Verbose:       verbose,
		Debug:         debug,
		SortBy:        sortBy,
		Spinner:       spinnerState{spin, isSpinner},
		ResultWriter:  cmd.OutOrStdout(),
	}, nil
}

func defaultIfError[T any](out T, err error) T {
	var defaultVal T

	if err != nil {
		return defaultVal
	}

	return out
}

func GetCliConfigOptions(cmd *cobra.Command) (bool, bool, error) {
	configName, err := cmd.Flags().GetString(ConfigFlag)
	if err != nil {
		return false, false, err
	}

	if configName == "" {
		return false, false, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return false, false, err
	}

	configDir := path.Join(home, "/.zot")

	isSpinner, err := parseBooleanConfig(configDir, configName, showspinnerConfig)
	if err != nil {
		return false, false, err
	}

	verifyTLS, err := parseBooleanConfig(configDir, configName, verifyTLSConfig)
	if err != nil {
		return false, false, err
	}

	return isSpinner, verifyTLS, nil
}

func GetServerURLFromFlags(cmd *cobra.Command) (string, error) {
	serverURL, err := cmd.Flags().GetString(URLFlag)
	if err == nil && serverURL != "" {
		return serverURL, nil
	}

	configName, err := cmd.Flags().GetString(ConfigFlag)
	if err != nil {
		return "", err
	}

	if configName == "" {
		return "", fmt.Errorf("%w: specify either '--%s' or '--%s' flags", zerr.ErrNoURLProvided, URLFlag, ConfigFlag)
	}

	serverURL, err = ReadServerURLFromConfig(configName)
	if err != nil {
		return serverURL, fmt.Errorf("reading url from config failed: %w", err)
	}

	if serverURL == "" {
		return "", fmt.Errorf("%w: url field from config is empty", zerr.ErrNoURLProvided)
	}

	if err := validateURL(serverURL); err != nil {
		return "", err
	}

	return serverURL, nil
}

func ReadServerURLFromConfig(configName string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	configDir := path.Join(home, "/.zot")

	urlFromConfig, err := getConfigValue(configDir, configName, "url")
	if err != nil {
		return "", err
	}

	return urlFromConfig, nil
}

func GetSuggestionsString(suggestions []string) string {
	if len(suggestions) > 0 {
		return "\n\nDid you mean this?\n" + "\t" + strings.Join(suggestions, "\n\t")
	}

	return ""
}

func ShowSuggestionsIfUnknownCommand(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}

	cmd.SuggestionsMinimumDistance = 2
	suggestions := GetSuggestionsString(cmd.SuggestionsFor(args[0]))

	return fmt.Errorf("%w '%s' for '%s'%s", zerr.ErrUnknownSubcommand, args[0], cmd.Name(), suggestions)
}
