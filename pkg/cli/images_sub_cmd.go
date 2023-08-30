//go:build search
// +build search

package cli

import (
	"fmt"
	"os"
	"path"

	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/cli/cmdflags"
	zcommon "zotregistry.io/zot/pkg/common"
)

func NewImageListCommand(searchService SearchService) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all images",
		Long:  "List all images",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			if err := CheckExtEndPointQuery(searchConfig, ImageListQuery()); err == nil {
				return SearchAllImagesGQL(searchConfig)
			}

			return SearchAllImages(searchConfig)
		},
	}
}

func NewImageCVEListCommand(searchService SearchService) *cobra.Command {
	var searchedCVEID string

	cmd := &cobra.Command{
		Use:   "cve [repo-name:tag][repo-name@digest]",
		Short: "List all CVE's of the image",
		Long:  "List all CVE's of the image",
		Args:  OneImageWithRefArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			if err := CheckExtEndPointQuery(searchConfig, CVEListForImageQuery()); err == nil {
				image := args[0]

				return SearchCVEForImageGQL(searchConfig, image, searchedCVEID)
			} else {
				return err
			}
		},
	}

	cmd.Flags().StringVar(&searchedCVEID, cmdflags.SearchedCVEID, "", "Search for a specific CVE by name/id")

	return cmd
}

func NewImageDerivedCommand(searchService SearchService) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "derived [repo-name:tag][repo-name@digest]",
		Short: "List images that are derived from given image",
		Long:  "List images that are derived from given image",
		Args:  OneImageWithRefArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			if err := CheckExtEndPointQuery(searchConfig, DerivedImageListQuery()); err == nil {
				return SearchDerivedImageListGQL(searchConfig, args[0])
			} else {
				return err
			}
		},
	}

	return cmd
}

func NewImageBaseCommand(searchService SearchService) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "base [repo-name:tag][repo-name@digest]",
		Short: "List images that are base for the given image",
		Long:  "List images that are base for the given image",
		Args:  OneImageWithRefArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			if err := CheckExtEndPointQuery(searchConfig, BaseImageListQuery()); err == nil {
				return SearchBaseImageListGQL(searchConfig, args[0])
			} else {
				return err
			}
		},
	}

	return cmd
}

func NewImageDigestCommand(searchService SearchService) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "digest [digest]",
		Short: "List images that contain a blob(manifest, config or layer) with the given digest",
		Long:  "List images that contain a blob(manifest, config or layer) with the given digest",
		Args:  OneDigestArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			if err := CheckExtEndPointQuery(searchConfig, ImageListForDigestQuery()); err == nil {
				return SearchImagesForDigestGQL(searchConfig, args[0])
			} else {
				return err
			}
		},
	}

	return cmd
}

func NewImageNameCommand(searchService SearchService) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "name [repo:tag]",
		Short: "List image details by name",
		Long:  "List image details by name",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}

			image := args[0]

			if dir, _ := zcommon.GetImageDirAndTag(image); dir == "" {
				return zerr.ErrInvalidRepoRefFormat
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			searchConfig, err := GetSearchConfigFromFlags(cmd, searchService)
			if err != nil {
				return err
			}

			if err := CheckExtEndPointQuery(searchConfig, ImageListQuery()); err == nil {
				return SearchImageByNameGQL(searchConfig, args[0])
			}

			return SearchImageByName(searchConfig, args[0])
		},
	}

	return cmd
}

func GetSearchConfigFromFlags(cmd *cobra.Command, searchService SearchService) (searchConfig, error) {
	serverURL, err := GetServerURLFromFlags(cmd)
	if err != nil {
		return searchConfig{}, err
	}

	isSpinner, verifyTLS := GetCliConfigOptions(cmd)

	flags := cmd.Flags()
	user := defaultIfError(flags.GetString(cmdflags.UserFlag))
	fixed := defaultIfError(flags.GetBool(cmdflags.FixedFlag))
	debug := defaultIfError(flags.GetBool(cmdflags.DebugFlag))
	verbose := defaultIfError(flags.GetBool(cmdflags.VerboseFlag))
	outputFormat := defaultIfError(flags.GetString(cmdflags.OutputFormatFlag))

	spin := spinner.New(spinner.CharSets[39], spinnerDuration, spinner.WithWriter(cmd.ErrOrStderr()))
	spin.Prefix = prefix

	return searchConfig{
		params:        map[string]*string{},
		searchService: searchService,
		servURL:       &serverURL,
		user:          &user,
		outputFormat:  &outputFormat,
		verifyTLS:     &verifyTLS,
		fixedFlag:     &fixed,
		verbose:       &verbose,
		debug:         &debug,
		spinner:       spinnerState{spin, isSpinner},
		resultWriter:  cmd.OutOrStdout(),
	}, nil
}

func defaultIfError[T any](out T, err error) T {
	var defaultVal T

	if err != nil {
		return defaultVal
	}

	return out
}

func GetCliConfigOptions(cmd *cobra.Command) (bool, bool) {
	configName, err := cmd.Flags().GetString(cmdflags.ConfigFlag)
	if err != nil {
		return false, false
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return false, false
	}

	configDir := path.Join(home, "/.zot")

	isSpinner, err := parseBooleanConfig(configDir, configName, showspinnerConfig)
	if err != nil {
		return false, false
	}

	verifyTLS, err := parseBooleanConfig(configDir, configName, verifyTLSConfig)
	if err != nil {
		return false, false
	}

	return isSpinner, verifyTLS
}

func GetServerURLFromFlags(cmd *cobra.Command) (string, error) {
	serverURL, err := cmd.Flags().GetString(cmdflags.URLFlag)
	if err == nil && serverURL != "" {
		return serverURL, nil
	}

	configName, err := cmd.Flags().GetString(cmdflags.ConfigFlag)
	if err != nil {
		return "", err
	}

	if configName == "" {
		return "", fmt.Errorf("%w: specify either '--%s' or '--%s' flags", zerr.ErrNoURLProvided, cmdflags.URLFlag,
			cmdflags.ConfigFlag)
	}

	serverURL, err = ReadServerURLFromConfig(configName)
	if err != nil {
		return serverURL, fmt.Errorf("reading url from config failed: %w", err)
	}

	if serverURL == "" {
		return "", fmt.Errorf("%w: url field from config is empty", zerr.ErrNoURLProvided)
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
