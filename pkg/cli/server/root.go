package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	glob "github.com/bmatcuk/doublestar/v4"
	"github.com/go-viper/mapstructure/v2"
	distspec "github.com/opencontainers/distribution-spec/specs-go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	eventsconf "zotregistry.dev/zot/v2/pkg/extensions/config/events"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	syncConstants "zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
)

// metadataConfig reports metadata after parsing, which we use to track
// errors.
func metadataConfig(md *mapstructure.Metadata) viper.DecoderConfigOption {
	return func(c *mapstructure.DecoderConfig) {
		c.Metadata = md
	}
}

func newServeCmd(conf *config.Config) *cobra.Command {
	// "serve"
	serveCmd := &cobra.Command{
		Use:     "serve <config>",
		Aliases: []string{"serve"},
		Short:   "`serve` stores and distributes OCI images",
		Long:    "`serve` stores and distributes OCI images",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := zlog.NewLogger("info", "")

			if len(args) > 0 {
				if err := LoadConfiguration(conf, args[0]); err != nil {
					return err
				}
			}

			ctlr := api.NewController(conf)

			ldapCredentials := ""

			if conf.HTTP.Auth != nil && conf.HTTP.Auth.LDAP != nil {
				ldapCredentials = conf.HTTP.Auth.LDAP.CredentialsFile
			}
			// config reloader
			hotReloader, err := NewHotReloader(ctlr, args[0], ldapCredentials)
			if err != nil {
				ctlr.Log.Error().Err(err).Msg("failed to create a new hot reloader")

				return err
			}

			hotReloader.Start()

			if err := ctlr.Init(); err != nil {
				ctlr.Log.Error().Err(err).Msg("failed to init controller")

				return err
			}

			initShutDownRoutine(ctlr)

			if err := ctlr.Run(); err != nil {
				logger.Error().Err(err).Msg("failed to start controller, exiting")
			}

			return nil
		},
	}

	return serveCmd
}

func newScrubCmd(conf *config.Config) *cobra.Command {
	// "scrub"
	scrubCmd := &cobra.Command{
		Use:     "scrub <config>",
		Aliases: []string{"scrub"},
		Short:   "`scrub` checks manifest/blob integrity",
		Long:    "`scrub` checks manifest/blob integrity",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := zlog.NewLogger("info", "")

			if len(args) > 0 {
				if err := LoadConfiguration(conf, args[0]); err != nil {
					return err
				}
			} else {
				if err := cmd.Usage(); err != nil {
					return err
				}

				return nil
			}

			// Do not show usage on errors which are not related to cummand line arguments
			cmd.SilenceUsage = true

			// checking if the server is  already running
			req, err := http.NewRequestWithContext(context.Background(),
				http.MethodGet,
				fmt.Sprintf("http://%s/v2", net.JoinHostPort(conf.HTTP.Address, conf.HTTP.Port)),
				nil)
			if err != nil {
				logger.Error().Err(err).Msg("failed to create a new http request")

				return err
			}

			response, err := http.DefaultClient.Do(req)
			if err == nil {
				response.Body.Close()
				logger.Warn().Err(zerr.ErrServerIsRunning).
					Msg("server is running, in order to perform the scrub command the server should be shut down")

				return zerr.ErrServerIsRunning
			} else {
				// server is down
				ctlr := api.NewController(conf)
				ctlr.Metrics = monitoring.NewMetricsServer(false, ctlr.Log)

				if err := ctlr.InitImageStore(); err != nil {
					return err
				}

				result, err := ctlr.StoreController.CheckAllBlobsIntegrity(cmd.Context())
				if err != nil {
					return err
				}

				result.PrintScrubResults(cmd.OutOrStdout())
			}

			return nil
		},
	}

	return scrubCmd
}

func newVerifyCmd(conf *config.Config) *cobra.Command {
	// verify
	verifyCmd := &cobra.Command{
		Use:     "verify <config>",
		Aliases: []string{"verify"},
		Short:   "`verify` validates a zot config file",
		Long:    "`verify` validates a zot config file",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := zlog.NewLogger("info", "")

			if len(args) > 0 {
				cmd.SilenceUsage = true

				if err := LoadConfiguration(conf, args[0]); err != nil {
					logger.Error().Str("config", args[0]).Msg("invalid config file")

					return err
				}

				logger.Info().Str("config", args[0]).Msg("config file is valid")
			}

			return nil
		},
	}

	return verifyCmd
}

func newVerifyFeatureCmd(conf *config.Config) *cobra.Command {
	verifyFeatureCmd := &cobra.Command{
		Use:   "verify-feature",
		Short: "`verify-feature` validates specific zot features",
		Long:  "`verify-feature` validates specific zot features",
	}

	// Add subcommands
	verifyFeatureCmd.AddCommand(newVerifyFeatureRetentionCmd(conf))

	return verifyFeatureCmd
}

// NewServerRootCmd creates a "zot" registry server command.
func NewServerRootCmd() *cobra.Command {
	showVersion := false
	conf := config.New()

	rootCmd := &cobra.Command{
		Use:   "zot",
		Short: "`zot`",
		Long:  "`zot`",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := zlog.NewLogger("info", "")

			if showVersion {
				commit, binaryType, goVersion, _ := conf.GetVersionInfo()
				logger.Info().Str("distribution-spec", distspec.Version).Str("commit", commit).
					Str("binary-type", binaryType).Str("go version", goVersion).Msg("version")
			} else {
				_ = cmd.Usage()
				cmd.SilenceErrors = false
			}

			return nil
		},
	}

	// "serve"
	rootCmd.AddCommand(newServeCmd(conf))
	// "verify"
	rootCmd.AddCommand(newVerifyCmd(conf))
	// "scrub"
	rootCmd.AddCommand(newScrubCmd(conf))
	// "verify-feature"
	rootCmd.AddCommand(newVerifyFeatureCmd(conf))
	// "version"
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "show the version and exit")

	return rootCmd
}

// isPathInside checks if path1 is inside path2 (path1 is a subdirectory of path2)
// This function is platform-agnostic and handles Windows drive letters, UNC paths, and symlinks.
func isPathInside(path1, path2 string) bool {
	// Normalize paths to absolute paths (handles platform-specific separators and symlinks)
	abs1, err1 := filepath.Abs(path1)
	abs2, err2 := filepath.Abs(path2)

	if err1 != nil || err2 != nil {
		return false
	}

	// On Windows, if paths are on different drives, filepath.Rel returns an error
	// which we handle by returning false (paths on different drives are not nested)
	rel, err := filepath.Rel(abs2, abs1)
	if err != nil {
		return false
	}

	// If the relative path doesn't start with "..", then path1 is inside path2
	// Also check that it's not "." (same directory) or empty (same path)
	// On Windows, filepath.Rel uses backslashes, but strings.HasPrefix works with any separator
	return rel != "." && rel != "" && !strings.HasPrefix(rel, "..")
}

// pathsConflict checks if two paths conflict (identical or nested) and returns:
// - 0: no conflict
// - 1: paths are identical
// - 2: path1 is inside path2
// - 3: path2 is inside path1.
func pathsConflict(path1, path2 string) int {
	if strings.EqualFold(path1, path2) {
		return 1
	}

	if isPathInside(path1, path2) {
		return 2
	}

	if isPathInside(path2, path1) {
		return 3
	}

	return 0
}

// getStorageType returns the storage driver type name.
// Returns "local" if StorageDriver is nil, otherwise extracts the name from StorageDriver["name"].
func getStorageType(storageDriver map[string]any) string {
	if storageDriver == nil {
		return storageConstants.LocalStorageDriverName
	}

	storeName := fmt.Sprintf("%v", storageDriver["name"])
	if storeName == storageConstants.S3StorageDriverName {
		return storageConstants.S3StorageDriverName
	}

	if storeName == storageConstants.GCSStorageDriverName {
		return storageConstants.GCSStorageDriverName
	}

	return storeName
}

func validateStorageConfig(cfg *config.Config, logger zlog.Logger) error {
	storageConfig := cfg.CopyStorageConfig()
	defaultRootDir := storageConfig.RootDirectory
	defaultStorageType := getStorageType(storageConfig.StorageDriver)

	// Collect all store root directories (default + substores) for nested path checking
	type storeInfo struct {
		route       string // empty for default store
		rootDir     string
		storageType string
	}
	allStores := make([]storeInfo, 0, 1+len(storageConfig.SubPaths))

	allStores = append(allStores, storeInfo{route: "", rootDir: defaultRootDir, storageType: defaultStorageType})
	for route, subStorageConfig := range storageConfig.SubPaths {
		allStores = append(allStores, storeInfo{
			route:       route,
			rootDir:     subStorageConfig.RootDirectory,
			storageType: getStorageType(subStorageConfig.StorageDriver),
		})
	}

	// Sort stores by route to ensure deterministic ordering
	slices.SortFunc(allStores, func(a, b storeInfo) int {
		return strings.Compare(a.route, b.route)
	})

	// Validate each store
	for _, store := range allStores {
		route := store.route
		rootDir := store.rootDir
		storageType := store.storageType

		// Check if this store conflicts with any other store of the same type (identical or nested paths)
		conflictingIdx := slices.IndexFunc(allStores, func(other storeInfo) bool {
			return other.route != route &&
				other.storageType == storageType &&
				pathsConflict(rootDir, other.rootDir) != 0
		})

		if conflictingIdx >= 0 {
			other := allStores[conflictingIdx]
			conflictType := pathsConflict(rootDir, other.rootDir)

			var storeName, otherStoreName string
			if route == "" {
				storeName = "default storage"
			} else {
				storeName = fmt.Sprintf("substore (route: %s)", route)
			}
			if other.route == "" {
				otherStoreName = "default storage"
			} else {
				otherStoreName = fmt.Sprintf("substore (route: %s)", other.route)
			}

			var msg string
			switch conflictType {
			case 1: // identical
				msg = fmt.Sprintf("invalid storage config, %s and %s cannot use the same root directory", storeName, otherStoreName)
			case 2: // rootDir is inside other.rootDir
				msg = fmt.Sprintf("invalid storage config, %s root directory cannot be inside %s root directory",
					storeName, otherStoreName)
			case 3: // other.rootDir is inside rootDir
				msg = fmt.Sprintf("invalid storage config, %s root directory cannot be inside %s root directory",
					otherStoreName, storeName)
			}

			logger.Error().Err(zerr.ErrBadConfig).
				Str("rootDir", rootDir).
				Str("otherRootDir", other.rootDir).
				Str("route", route).
				Str("otherRoute", other.route).
				Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}
	}

	return nil
}

func validateCacheConfig(cfg *config.Config, logger zlog.Logger) error {
	// global
	storageConfig := cfg.CopyStorageConfig()
	// dedupe true, remote storage, remoteCache true, but no cacheDriver (remote)
	//nolint: lll
	if storageConfig.Dedupe && storageConfig.StorageDriver != nil && storageConfig.RemoteCache && storageConfig.CacheDriver == nil {
		msg := "invalid database config, dedupe set to true with remote storage and database, but no remote database configured"
		logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	if storageConfig.CacheDriver != nil && storageConfig.RemoteCache {
		// local storage with remote database
		// redis is supported with both local and S3 storage, while dynamodb is only supported with S3
		// redis is only supported with local storage in a non-clustering scenario with a single zot instance,
		if storageConfig.StorageDriver == nil && storageConfig.CacheDriver["name"] != storageConstants.RedisDriverName {
			msg := "invalid database config, cannot have local storage driver with remote database!"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}

		// unsupported database driver
		if storageConfig.CacheDriver["name"] != storageConstants.DynamoDBDriverName &&
			storageConfig.CacheDriver["name"] != storageConstants.RedisDriverName {
			msg := "invalid database config, unsupported database driver"
			logger.Error().Err(zerr.ErrBadConfig).Interface("cacheDriver", storageConfig.CacheDriver["name"]).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}
	}

	if !storageConfig.RemoteCache && storageConfig.CacheDriver != nil {
		logger.Warn().Err(zerr.ErrBadConfig).Str("directory", storageConfig.RootDirectory).
			Msg("invalid database config, remoteCache set to false but cacheDriver config (remote database)" +
				" provided for directory will ignore and use local database")
	}

	// subpaths
	for _, subPath := range storageConfig.SubPaths {
		// dedupe true, remote storage, remoteCache true, but no cacheDriver (remote)
		//nolint: lll
		if subPath.Dedupe && subPath.StorageDriver != nil && subPath.RemoteCache && subPath.CacheDriver == nil {
			msg := "invalid database config, dedupe set to true with remote storage and database, but no remote database configured!"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}

		if subPath.CacheDriver != nil && subPath.RemoteCache {
			// local storage with remote caching
			if subPath.StorageDriver == nil {
				msg := "invalid database config, cannot have local storage driver with remote database!"
				logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

				return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
			}

			// unsupported cache driver
			if subPath.CacheDriver["name"] != storageConstants.DynamoDBDriverName {
				msg := "invalid database config, unsupported database driver"
				logger.Error().Err(zerr.ErrBadConfig).Interface("cacheDriver", subPath.CacheDriver["name"]).Msg(msg)

				return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
			}
		}

		if !subPath.RemoteCache && subPath.CacheDriver != nil {
			logger.Warn().Err(zerr.ErrBadConfig).Str("directory", subPath.RootDirectory).
				Msg("invalid database config, remoteCache set to false but cacheDriver config (remote database)" +
					"provided for directory, will ignore and use local database")
		}
	}

	return nil
}

func validateRemoteSessionStoreConfig(cfg *config.Config, logger zlog.Logger) error {
	// it is okay for the session driver config to be nil
	// this is backwards compatible for older configs
	authConfig := cfg.CopyAuthConfig()
	if authConfig == nil || authConfig.SessionDriver == nil {
		return nil
	}

	sessionDriverName, ok := authConfig.SessionDriver["name"]
	if !ok {
		msg := "must provide session driver name!"
		logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	allowedDriverNames := []string{
		storageConstants.RedisDriverName,
		storageConstants.LocalStorageDriverName,
	}

	isValidDriver := false

	for _, allowedDriverName := range allowedDriverNames {
		if allowedDriverName == sessionDriverName {
			isValidDriver = true

			break
		}
	}

	if !isValidDriver {
		msg := fmt.Sprintf("session store driver %s is not allowed!", sessionDriverName)
		logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	// If the redis driver is being used, then session keys must not be configured
	// as redis session store does not support these yet.

	if sessionDriverName == storageConstants.RedisDriverName {
		if authConfig.SessionKeysFile != "" {
			msg := "session keys not supported when redis session driver is used!"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}
	}

	return nil
}

func validateExtensionsConfig(cfg *config.Config, logger zlog.Logger) error {
	extensionsConfig := cfg.CopyExtensionsConfig()
	if extensionsConfig != nil && extensionsConfig.Mgmt != nil {
		logger.Warn().Msg("mgmt extensions configuration option has been made redundant and will be ignored.")
	}

	if extensionsConfig != nil && extensionsConfig.APIKey != nil {
		logger.Warn().Msg("apikey extension configuration will be ignored as API keys " +
			"are now configurable in the HTTP settings.")
	}

	if extensionsConfig.IsUIEnabled() {
		// it would make sense to also check for mgmt and user prefs to be enabled,
		// but those are both enabled by having the search and ui extensions enabled
		if !extensionsConfig.IsSearchEnabled() {
			msg := "failed to enable ui, search extension must be enabled"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}
	}

	//nolint:lll
	storageConfig := cfg.CopyStorageConfig()
	if storageConfig.StorageDriver != nil && extensionsConfig.IsCveScanningEnabled() {
		msg := "failed to enable cve scanning due to incompatibility with remote storage, please disable cve"
		logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	for _, subPath := range storageConfig.SubPaths {
		//nolint:lll
		if subPath.StorageDriver != nil && extensionsConfig.IsCveScanningEnabled() {
			msg := "failed to enable cve scanning due to incompatibility with remote storage, please disable cve"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}
	}

	return nil
}

func validateStorageConfigSection(
	cfg *config.Config, logger zlog.Logger, storageConfig config.GlobalStorageConfig,
) error {
	if len(storageConfig.StorageDriver) != 0 {
		// enforce s3/gcs driver in case of using storage driver
		if storageConfig.StorageDriver["name"] != storageConstants.S3StorageDriverName &&
			storageConfig.StorageDriver["name"] != storageConstants.GCSStorageDriverName {
			msg := "unsupported storage driver"
			logger.Error().Err(zerr.ErrBadConfig).Interface("storageDriver", storageConfig.StorageDriver["name"]).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}

		// enforce tmpDir in case sync + s3/gcs
		extensionsConfig := cfg.CopyExtensionsConfig()
		if extensionsConfig.IsSyncEnabled() && extensionsConfig.Sync.DownloadDir == "" {
			msg := "using both sync and remote storage features needs config.Extensions.Sync.DownloadDir to be specified"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}
	}

	// enforce s3/gcs driver on subpaths in case of using storage driver
	if len(storageConfig.SubPaths) > 0 {
		for route, subStorageConfig := range storageConfig.SubPaths {
			if len(subStorageConfig.StorageDriver) != 0 {
				if subStorageConfig.StorageDriver["name"] != storageConstants.S3StorageDriverName &&
					subStorageConfig.StorageDriver["name"] != storageConstants.GCSStorageDriverName {
					msg := "unsupported storage driver"
					logger.Error().Err(zerr.ErrBadConfig).Str("subpath", route).Interface("storageDriver",
						subStorageConfig.StorageDriver["name"]).Msg(msg)

					return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
				}

				// enforce tmpDir in case sync + s3/gcs
				extensionsConfig := cfg.CopyExtensionsConfig()
				if extensionsConfig.IsSyncEnabled() && extensionsConfig.Sync.DownloadDir == "" {
					msg := "using both sync and remote storage features needs config.Extensions.Sync.DownloadDir to be specified"
					logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

					return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
				}
			}
		}
	}

	return nil
}

func validateConfiguration(config *config.Config, logger zlog.Logger) error {
	if err := validateHTTP(config, logger); err != nil {
		return err
	}

	if err := validateGC(config, logger); err != nil {
		return err
	}

	if err := validateLDAP(config, logger); err != nil {
		return err
	}

	if err := validateMTLS(config, logger); err != nil {
		return err
	}

	if err := validateOpenIDConfig(config, logger); err != nil {
		return err
	}

	if err := validateBearerConfig(config, logger); err != nil {
		return err
	}

	if err := validateSync(config, logger); err != nil {
		return err
	}

	if err := validateStorageConfig(config, logger); err != nil {
		return err
	}

	if err := validateCacheConfig(config, logger); err != nil {
		return err
	}

	if err := validateRemoteSessionStoreConfig(config, logger); err != nil {
		return err
	}

	if err := validateExtensionsConfig(config, logger); err != nil {
		return err
	}

	// check authorization config, it should have basic auth enabled or ldap, api keys or OpenID
	accessControlConfig := config.CopyAccessControlConfig()
	if accessControlConfig != nil {
		// checking for anonymous policy only authorization config: no users, no policies but anonymous policy
		if err := validateAuthzPolicies(config, logger); err != nil {
			return err
		}
	}

	storageConfig := config.CopyStorageConfig()
	if err := validateStorageConfigSection(config, logger, storageConfig); err != nil {
		return err
	}

	// check glob patterns in authz config are compilable
	if accessControlConfig != nil {
		for pattern := range accessControlConfig.Repositories {
			ok := glob.ValidatePattern(pattern)
			if !ok {
				msg := "failed to compile authorization pattern"
				logger.Error().Err(glob.ErrBadPattern).Str("pattern", pattern).Msg(msg)

				return fmt.Errorf("%w: %s", glob.ErrBadPattern, msg)
			}
		}
	}

	// check validity of scale out cluster config
	if err := validateClusterConfig(config, logger); err != nil {
		return err
	}

	return nil
}

func validateOpenIDConfig(cfg *config.Config, logger zlog.Logger) error {
	authConfig := cfg.CopyAuthConfig()
	// can't check with IsOpenIDAuthEnabled(), because it can't test invalid providers
	if authConfig != nil && authConfig.OpenID != nil && len(authConfig.OpenID.Providers) > 0 {
		for provider, providerConfig := range authConfig.OpenID.Providers {
			//nolint: gocritic
			if config.IsOpenIDSupported(provider) {
				if providerConfig.ClientID == "" || providerConfig.Issuer == "" ||
					len(providerConfig.Scopes) == 0 {
					msg := "OpenID provider config requires clientid, issuer and scopes parameters"
					logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

					return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
				}
			} else if config.IsOauth2Supported(provider) {
				if providerConfig.ClientID == "" || len(providerConfig.Scopes) == 0 {
					msg := "OAuth2 provider config requires clientid and scopes parameters"
					logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

					return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
				}
			} else {
				msg := "unsupported openid/oauth2 provider"
				logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

				return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
			}
		}
	}

	return nil
}

func validateBearerConfig(cfg *config.Config, logger zlog.Logger) error {
	authConfig := cfg.CopyAuthConfig()
	if authConfig == nil || authConfig.Bearer == nil {
		return nil
	}

	bearer := authConfig.Bearer

	if bearer.Cert != "" && bearer.AWSSecretsManager != nil {
		msg := "cannot configure both cert and awsSecretsManager for bearer authentication"
		logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	if bearer.AWSSecretsManager != nil {
		asm := bearer.AWSSecretsManager

		if asm.Region == "" {
			msg := "awsSecretsManager region must be specified"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}

		if asm.SecretName == "" {
			msg := "awsSecretsManager secretName must be specified"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}

		if asm.RefreshInterval < 0 {
			msg := "awsSecretsManager refreshInterval must be non-negative"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}
	}

	return nil
}

func validateAuthzPolicies(config *config.Config, logger zlog.Logger) error {
	authConfig := config.CopyAuthConfig()
	accessControlConfig := config.CopyAccessControlConfig()

	logger.Info().Msg("checking if anonymous authorization is the only type of authorization policy configured")

	if !authConfig.IsBasicAuthnEnabled() && !config.IsMTLSAuthEnabled() && !authConfig.IsBearerAuthEnabled() &&
		!accessControlConfig.ContainsOnlyAnonymousPolicy() {
		msg := "access control config requires one of htpasswd, ldap, openid or mTLS authentication " +
			"or using only 'anonymousPolicy' policies"
		logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	return nil
}

//nolint:gocyclo,cyclop,nestif
func applyDefaultValues(config *config.Config, viperInstance *viper.Viper, logger zlog.Logger) {
	defaultVal := true

	if config.Extensions == nil && viperInstance.Get("extensions") != nil {
		config.Extensions = &extconf.ExtensionConfig{}

		extMap := viperInstance.GetStringMap("extensions")
		_, ok := extMap["metrics"]

		if ok {
			// we found a config like `"extensions": {"metrics": {}}`
			// Note: In case metrics is not empty the config.Extensions will not be nil and we will not reach here
			config.Extensions.Metrics = &extconf.MetricsConfig{}
		}

		_, ok = extMap["search"]
		if ok {
			// we found a config like `"extensions": {"search": {}}`
			// Note: In case search is not empty the config.Extensions will not be nil and we will not reach here
			config.Extensions.Search = &extconf.SearchConfig{}
		}

		_, ok = extMap["scrub"]
		if ok {
			// we found a config like `"extensions": {"scrub:": {}}`
			// Note: In case scrub is not empty the config.Extensions will not be nil and we will not reach here
			config.Extensions.Scrub = &extconf.ScrubConfig{}
		}

		_, ok = extMap["trust"]
		if ok {
			// we found a config like `"extensions": {"trust:": {}}`
			// Note: In case trust is not empty the config.Extensions will not be nil and we will not reach here
			config.Extensions.Trust = &extconf.ImageTrustConfig{}
		}

		_, ok = extMap["ui"]
		if ok {
			// we found a config like `"extensions": {"ui:": {}}`
			// Note: In case UI is not empty the config.Extensions will not be nil and we will not reach here
			config.Extensions.UI = &extconf.UIConfig{}
		}
	}

	if config.Extensions != nil {
		if config.Extensions.Sync != nil {
			if config.Extensions.Sync.Enable == nil {
				config.Extensions.Sync.Enable = &defaultVal
			}

			for idx := range config.Extensions.Sync.Registries {
				regCfg := &config.Extensions.Sync.Registries[idx]
				if regCfg.TLSVerify == nil {
					regCfg.TLSVerify = &defaultVal
				}

				if regCfg.SyncTimeout == 0 {
					regCfg.SyncTimeout = syncConstants.DefaultSyncTimeout
				}

				if regCfg.ResponseHeaderTimeout == 0 {
					regCfg.ResponseHeaderTimeout = syncConstants.DefaultResponseHeaderTimeout
				}
			}
		}

		if config.Extensions.Search != nil {
			if config.Extensions.Search.Enable == nil {
				config.Extensions.Search.Enable = &defaultVal
			}

			if *config.Extensions.Search.Enable && config.Extensions.Search.CVE != nil {
				defaultUpdateInterval, _ := time.ParseDuration("2h")

				if config.Extensions.Search.CVE.UpdateInterval < defaultUpdateInterval {
					config.Extensions.Search.CVE.UpdateInterval = defaultUpdateInterval

					logger.Warn().Msg("cve update interval set to too-short interval < 2h, " +
						"changing update duration to 2 hours and continuing.")
				}

				if config.Extensions.Search.CVE.Trivy == nil {
					config.Extensions.Search.CVE.Trivy = &extconf.TrivyConfig{}
				}

				if config.Extensions.Search.CVE.Trivy.DBRepository == "" {
					defaultDBDownloadURL := "ghcr.io/aquasecurity/trivy-db"
					logger.Info().Str("url", defaultDBDownloadURL).Str("component", "config").
						Msg("using default trivy-db download URL.")

					config.Extensions.Search.CVE.Trivy.DBRepository = defaultDBDownloadURL
				}

				if config.Extensions.Search.CVE.Trivy.JavaDBRepository == "" {
					defaultJavaDBDownloadURL := "ghcr.io/aquasecurity/trivy-java-db"
					logger.Info().Str("url", defaultJavaDBDownloadURL).Str("component", "config").
						Msg("using default trivy-java-db download URL.")

					config.Extensions.Search.CVE.Trivy.JavaDBRepository = defaultJavaDBDownloadURL
				}
			}
		}

		if config.Extensions.Metrics != nil {
			if config.Extensions.Metrics.Enable == nil {
				config.Extensions.Metrics.Enable = &defaultVal
			}

			if config.Extensions.Metrics.Prometheus == nil {
				config.Extensions.Metrics.Prometheus = &extconf.PrometheusConfig{Path: constants.DefaultMetricsExtensionRoute}
			}
		}

		if config.Extensions.Scrub != nil {
			if config.Extensions.Scrub.Enable == nil {
				config.Extensions.Scrub.Enable = &defaultVal
			}

			if config.Extensions.Scrub.Interval == 0 {
				config.Extensions.Scrub.Interval = 24 * time.Hour //nolint:mnd
			}

			// Validate minimum scrub interval
			minScrubInterval, _ := time.ParseDuration("2h")
			if config.Extensions.Scrub.Interval < minScrubInterval {
				config.Extensions.Scrub.Interval = minScrubInterval

				logger.Warn().Msg("scrub interval set to too-short interval < 2h, " +
					"changing scrub duration to 2 hours and continuing.")
			}
		}

		if config.Extensions.UI != nil {
			if config.Extensions.UI.Enable == nil {
				config.Extensions.UI.Enable = &defaultVal
			}
		}

		if config.Extensions.Trust != nil {
			if config.Extensions.Trust.Enable == nil {
				config.Extensions.Trust.Enable = &defaultVal
			}
		}
	}

	// set default values in case GC is disabled
	if !config.Storage.GC {
		if viperInstance.Get("storage::gcdelay") == nil {
			config.Storage.GCDelay = 0
		}

		if viperInstance.Get("storage::retention::delay") == nil {
			config.Storage.Retention.Delay = 0
		}

		if viperInstance.Get("storage::gcinterval") == nil {
			config.Storage.GCInterval = 0
		}
	} else if !viperInstance.IsSet("storage::retention::delay") {
		// if GC is enabled, retentionDelay is set to gcDelay by default
		// it could be default gcDelay or the custom value set in the config file
		config.Storage.Retention.Delay = config.Storage.GCDelay
	}

	// apply deleteUntagged default
	for idx := range config.Storage.Retention.Policies {
		if !viperInstance.IsSet("storage::retention::policies::" + strconv.Itoa(idx) + "::deleteUntagged") {
			config.Storage.Retention.Policies[idx].DeleteUntagged = &defaultVal
		}
	}

	// cache settings

	// global storage

	// if dedupe is true but remoteCache bool not set in config file
	// for cloud based storage, remoteCache defaults to true
	if config.Storage.Dedupe && !viperInstance.IsSet("storage::remotecache") && config.Storage.StorageDriver != nil {
		config.Storage.RemoteCache = true
	}

	if config.Storage.StorageDriver != nil {
		// s3 dedup=false, check for previous dedupe usage and set to true if cachedb found
		if !config.Storage.Dedupe {
			cacheDir, _ := config.Storage.StorageDriver["rootdirectory"].(string)
			cachePath := path.Join(cacheDir, storageConstants.BoltdbName+storageConstants.DBExtensionName)

			if _, err := os.Stat(cachePath); err == nil {
				logger.Info().Str("component", "config").Msg("dedupe set to false for s3 driver but used to be true.")
				logger.Info().Str("cache path", cachePath).Msg("found cache database")

				config.Storage.RemoteCache = false
			}
		}

		// backward compatibility for s3 storage driver
		// if regionendpoint is provided, forcepathstyle should be set to true
		// ref: https://github.com/distribution/distribution/pull/4291
		if config.Storage.StorageDriver["name"] == storageConstants.S3StorageDriverName {
			_, hasRegionEndpoint := config.Storage.StorageDriver["regionendpoint"]
			_, hasForcePathStyle := config.Storage.StorageDriver["forcepathstyle"]

			if hasRegionEndpoint && !hasForcePathStyle {
				logger.Warn().
					Msg("deprecated: automatically setting forcepathstyle to true for s3 storage driver.")
				config.Storage.StorageDriver["forcepathstyle"] = true
			}
		}
	}

	// subpaths
	for name, storageConfig := range config.Storage.SubPaths {
		// if dedupe is true but remoteCache bool not set in config file
		// for cloud based storage, remoteCache defaults to true
		if storageConfig.Dedupe && !viperInstance.IsSet("storage::subpaths::"+name+"::remotecache") && storageConfig.StorageDriver != nil { //nolint:lll
			storageConfig.RemoteCache = true
		}

		// s3 dedup=false, check for previous dedupe usage and set to true if cachedb found
		if !storageConfig.Dedupe && storageConfig.StorageDriver != nil {
			subpathCacheDir, _ := storageConfig.StorageDriver["rootdirectory"].(string)
			subpathCachePath := path.Join(subpathCacheDir, storageConstants.BoltdbName+storageConstants.DBExtensionName)

			if _, err := os.Stat(subpathCachePath); err == nil {
				logger.Info().Str("component", "config").Msg("dedupe set to false for s3 driver but used to be true. ")
				logger.Info().Str("cache path", subpathCachePath).Msg("found cache database")

				storageConfig.RemoteCache = false
			}
		}

		// if gc is enabled
		if storageConfig.GC {
			// and gcDelay is not set, it is set to default value
			if !viperInstance.IsSet("storage::subpaths::" + name + "::gcdelay") {
				storageConfig.GCDelay = storageConstants.DefaultGCDelay
			}

			// and retentionDelay is not set, it is set to default value
			if !viperInstance.IsSet("storage::subpaths::" + name + "::retention::delay") {
				// retentionDelay is set to gcDelay by default
				// it could be default gcDelay or the custom value set in the config file
				storageConfig.Retention.Delay = storageConfig.GCDelay
			}

			// and gcInterval is not set, it is set to default value
			if !viperInstance.IsSet("storage::subpaths::" + name + "::gcinterval") {
				storageConfig.GCInterval = storageConstants.DefaultGCInterval
			}
		}

		// apply deleteUntagged default
		for idx := range storageConfig.Retention.Policies {
			deleteUntaggedKey := fmt.Sprintf("storage::subpaths::%s::retention::policies::%d::deleteUntagged",
				name, idx,
			)
			if !viperInstance.IsSet(deleteUntaggedKey) {
				storageConfig.Retention.Policies[idx].DeleteUntagged = &defaultVal
			}
		}

		config.Storage.SubPaths[name] = storageConfig
	}

	// if OpenID authentication is enabled,
	// API Keys are also enabled in order to provide data path authentication
	if config.HTTP.Auth != nil && config.HTTP.Auth.OpenID != nil {
		config.HTTP.Auth.APIKey = true
	}
}

func updateDistSpecVersion(config *config.Config, logger zlog.Logger) {
	if config.DistSpecVersion == distspec.Version {
		return
	}

	logger.Warn().Str("config version", config.DistSpecVersion).Str("supported version", distspec.Version).
		Msg("config dist-spec version differs from version actually used")

	config.DistSpecVersion = distspec.Version
}

func LoadConfiguration(config *config.Config, configPath string) error {
	logger := zlog.NewLogger("info", "")

	// Default is dot (.) but because we allow glob patterns in authz
	// we need another key delimiter.
	viperInstance := viper.NewWithOptions(viper.KeyDelimiter("::"))

	ext := filepath.Ext(configPath)
	ext = strings.Replace(ext, ".", "", 1)

	/* if file extension is not supported, try everything
	it's also possible that the filename is starting with a dot eg: ".config". */
	if !slices.Contains(viper.SupportedExts, ext) {
		ext = ""
	}

	switch ext {
	case "":
		logger.Info().Str("path", configPath).Msg("config file with no extension, trying all supported config types")

		var err error

		for _, configType := range viper.SupportedExts {
			viperInstance.SetConfigType(configType)
			viperInstance.SetConfigFile(configPath)

			err = viperInstance.ReadInConfig()
			if err == nil {
				break
			}
		}

		if err != nil {
			logger.Error().Err(err).Str("path", configPath).Msg("failed to read configuration, tried all supported config types")

			return err
		}
	default:
		viperInstance.SetConfigFile(configPath)

		if err := viperInstance.ReadInConfig(); err != nil {
			logger.Error().Err(err).Str("path", configPath).Msg("failed to read configuration")

			return err
		}
	}

	metaData := &mapstructure.Metadata{}

	decoderOpts := []viper.DecoderConfigOption{
		metadataConfig(metaData),
		viper.DecodeHook(
			mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				eventsconf.SinkConfigDecoderHook(),
			),
		),
	}

	if err := viperInstance.UnmarshalExact(&config, decoderOpts...); err != nil {
		logger.Error().Err(err).Msg("failed to unmarshal new config")

		return err
	}

	// Validate log level before creating logger to avoid panic
	if _, err := zlog.ParseLevel(config.Log.Level); err != nil {
		logger.Error().Err(zerr.ErrBadConfig).Str("level", config.Log.Level).Msg(err.Error())

		return err
	}

	log := zlog.NewLogger(config.Log.Level, config.Log.Output)

	if len(metaData.Keys) == 0 {
		msg := "failed to load config due to the absence of any key:value pair"
		logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	if len(metaData.Unused) > 0 {
		msg := "failed to load config due to unknown keys"
		logger.Error().Err(zerr.ErrBadConfig).Strs("keys", metaData.Unused).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	if err := updateLDAPConfig(config); err != nil {
		logger.Error().Err(err).Msg("failed to read ldap config file")

		return err
	}

	if err := updateOpenIDConfig(config); err != nil {
		logger.Error().Err(err).Msg("failed to read openid provider config file(s)")

		return err
	}

	if err := loadSessionKeys(config); err != nil {
		logger.Error().Err(err).Msg("failed to read sessionKeysFile")

		return err
	}

	// defaults
	applyDefaultValues(config, viperInstance, log)

	// various config checks
	if err := validateConfiguration(config, log); err != nil {
		return err
	}

	// update distSpecVersion
	updateDistSpecVersion(config, log)

	return nil
}

func loadSessionKeys(conf *config.Config) error {
	if conf.HTTP.Auth != nil && conf.HTTP.Auth.SessionKeysFile != "" {
		var sessionKeys config.SessionKeys

		if err := readSecretFile(conf.HTTP.Auth.SessionKeysFile, &sessionKeys, false); err != nil {
			return err
		}

		if sessionKeys.HashKey != "" {
			conf.HTTP.Auth.SessionHashKey = []byte(sessionKeys.HashKey)
		}

		if sessionKeys.EncryptKey != "" {
			conf.HTTP.Auth.SessionEncryptKey = []byte(sessionKeys.EncryptKey)
		}
	}

	return nil
}

func updateLDAPConfig(conf *config.Config) error {
	if conf.HTTP.Auth == nil || conf.HTTP.Auth.LDAP == nil {
		return nil
	}

	if conf.HTTP.Auth.LDAP.CredentialsFile == "" {
		conf.HTTP.Auth.LDAP.SetBindDN("anonym-user")

		return nil
	}

	var newLDAPCredentials config.LDAPCredentials

	if err := readSecretFile(conf.HTTP.Auth.LDAP.CredentialsFile, &newLDAPCredentials, true); err != nil {
		return err
	}

	conf.HTTP.Auth.LDAP.SetBindDN(newLDAPCredentials.BindDN)
	conf.HTTP.Auth.LDAP.SetBindPassword(newLDAPCredentials.BindPassword)

	return nil
}

func updateOpenIDConfig(conf *config.Config) error {
	logger := zlog.NewLogger("info", "")

	if conf.HTTP.Auth == nil || conf.HTTP.Auth.OpenID == nil {
		return nil
	}

	for name, provider := range conf.HTTP.Auth.OpenID.Providers {
		if provider.CredentialsFile != "" {
			var newOpenIDCredentials config.OpenIDCredentials

			if err := readSecretFile(provider.CredentialsFile, &newOpenIDCredentials, true); err != nil {
				return err
			}

			provider.ClientID = newOpenIDCredentials.ClientID
			provider.ClientSecret = newOpenIDCredentials.ClientSecret

			conf.HTTP.Auth.OpenID.Providers[name] = provider
		} else {
			logger.Warn().Str("provider", name).
				Msg("deprecated: use the new OpenID provider credentialsfile instead of clientid and clientsecret.")
		}
	}

	return nil
}

func readSecretFile(path string, v any, checkUnsetFields bool) error { //nolint: varnamelen
	logger := zlog.NewLogger("info", "")

	viperInstance := viper.NewWithOptions(viper.KeyDelimiter("::"))

	viperInstance.SetConfigFile(path)

	if err := viperInstance.ReadInConfig(); err != nil {
		logger.Error().Err(err).Str("path", path).Msg("failed to read secret file configuration")

		return errors.Join(zerr.ErrBadConfig, err)
	}

	metaData := &mapstructure.Metadata{}
	if err := viperInstance.Unmarshal(v, metadataConfig(metaData)); err != nil {
		logger.Error().Err(err).Str("path", path).Msg("failed to unmarshal secret file config")

		return errors.Join(zerr.ErrBadConfig, err)
	}

	if len(metaData.Keys) == 0 {
		msg := "failed to load secret file due to the absence of any key:value pair"
		logger.Error().Err(zerr.ErrBadConfig).Str("path", path).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	if len(metaData.Unused) > 0 {
		msg := "failed to load secret file due to unknown keys"
		logger.Error().Err(zerr.ErrBadConfig).Str("path", path).Strs("keys", metaData.Unused).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	if checkUnsetFields && len(metaData.Unset) > 0 {
		msg := "failed to load secret file due to unset keys"
		logger.Error().Err(zerr.ErrBadConfig).Strs("keys", metaData.Unset).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	return nil
}

func validateLDAP(config *config.Config, logger zlog.Logger) error {
	// LDAP mandatory configuration
	authConfig := config.CopyAuthConfig()
	if authConfig.IsLdapAuthEnabled() {
		ldap := authConfig.LDAP
		if ldap.UserAttribute == "" {
			msg := "invalid LDAP configuration, missing mandatory key: userAttribute"
			logger.Error().Str("userAttribute", ldap.UserAttribute).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrLDAPConfig, msg)
		}

		if ldap.Address == "" {
			msg := "invalid LDAP configuration, missing mandatory key: address"
			logger.Error().Str("address", ldap.Address).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrLDAPConfig, msg)
		}

		if ldap.BaseDN == "" {
			msg := "invalid LDAP configuration, missing mandatory key: basedn"
			logger.Error().Str("basedn", ldap.BaseDN).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrLDAPConfig, msg)
		}
	}

	return nil
}

// validateMTLS checks if the authentication settings for MTLS are valid.
func validateMTLS(config *config.Config, logger zlog.Logger) error {
	mtlsConfig := config.CopyAuthConfig().GetMTLSConfig()
	if mtlsConfig == nil {
		return nil
	}

	// If mTLS config is present, TLS must be properly configured
	if !config.IsMTLSAuthEnabled() {
		msg := "mTLS configuration requires TLS to be enabled with CA certificate"
		logger.Error().Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	if len(mtlsConfig.IdentityAttibutes) > 0 {
		validIdentityAttributes := []string{
			"CommonName", "CN", "Subject", "DN", "Email", "rfc822name", "URI", "URL", "DNSName", "DNS",
		}

		var unrecognizedIdentityAttributes []string

		for _, source := range mtlsConfig.IdentityAttibutes {
			idx := slices.IndexFunc(validIdentityAttributes,
				func(s string) bool {
					return strings.EqualFold(strings.TrimSpace(source), strings.TrimSpace(s))
				},
			)

			if idx < 0 {
				unrecognizedIdentityAttributes = append(unrecognizedIdentityAttributes, source)
			}
		}

		if len(unrecognizedIdentityAttributes) > 0 {
			logger.Error().Strs("identityAttributes", unrecognizedIdentityAttributes).Msg("unsupported identityAttributes")

			return fmt.Errorf("%w: %s", zerr.ErrUnsupportedIdentityAttribute, strings.Join(unrecognizedIdentityAttributes, ","))
		}
	}

	idx := slices.IndexFunc(mtlsConfig.IdentityAttibutes,
		func(s string) bool {
			return strings.ToLower(strings.TrimSpace(s)) == "uri" || strings.ToLower(strings.TrimSpace(s)) == "url"
		},
	)

	useSan := idx >= 0

	if mtlsConfig.DNSANIndex != 0 && !useSan {
		logger.Error().Int("dnsSanIndex", mtlsConfig.DNSANIndex).Strs("identityAttributes", mtlsConfig.IdentityAttibutes).
			Msg("dnsSanIndex is only supported for URI/URL MTLS identity attribute")

		return fmt.Errorf("%w: dnsSanIndex is only supported for URI/URL MTLS identity attribute",
			zerr.ErrBadConfig)
	}

	if mtlsConfig.EmailSANIndex != 0 && !useSan {
		logger.Error().Int("emailSanIndex", mtlsConfig.EmailSANIndex).
			Strs("identityAttributes", mtlsConfig.IdentityAttibutes).
			Msg("emailSanIndex is only supported for URI/URL MTLS identity attribute")

		return fmt.Errorf("%w: emailSanIndex is only supported for URI/URL MTLS identity attribute",
			zerr.ErrBadConfig)
	}

	if mtlsConfig.URISANIndex != 0 && !useSan {
		logger.Error().Int("uriSanIndex", mtlsConfig.URISANIndex).Strs("identityAttributes", mtlsConfig.IdentityAttibutes).
			Msg("uriSanIndex is only supported for URI/URL MTLS identity attribute")

		return fmt.Errorf("%w: uriSanIndex is only supported for URI/URL MTLS identity attribute",
			zerr.ErrBadConfig)
	}

	if mtlsConfig.URISANPattern != "" {
		if !useSan {
			logger.Error().Str("uriSanPattern", mtlsConfig.URISANPattern).
				Strs("identityAttributes", mtlsConfig.IdentityAttibutes).
				Msg("uriSanPattern is only supported for URI/URL MTLS identity attribute")

			return fmt.Errorf("%w: uriSanPattern is only supported for URI/URL MTLS identity attribute",
				zerr.ErrBadConfig)
		}

		if _, err := regexp.Compile(mtlsConfig.URISANPattern); err != nil {
			logger.Error().Str("uriSanPattern", mtlsConfig.URISANPattern).Msg("invalid regex pattern")

			return fmt.Errorf("%w: %s", zerr.ErrInvalidURISANPattern, mtlsConfig.URISANPattern)
		}
	}

	return nil
}

func validateHTTP(config *config.Config, logger zlog.Logger) error {
	port := config.GetHTTPPort()
	if port != "" {
		portInt, err := strconv.ParseInt(port, 10, 64)
		if err != nil || (portInt < 0 || portInt > 65535) {
			logger.Error().Str("port", port).Msg("invalid port")

			return fmt.Errorf("%w: invalid port %s", zerr.ErrBadConfig, port)
		}
	}

	return nil
}

func validateGC(config *config.Config, logger zlog.Logger) error {
	// enforce GC params
	storageConfig := config.CopyStorageConfig()
	if storageConfig.GCDelay < 0 {
		logger.Error().Err(zerr.ErrBadConfig).Dur("delay", storageConfig.GCDelay).
			Msg("invalid garbage-collect delay specified")

		return fmt.Errorf("%w: invalid garbage-collect delay specified %s",
			zerr.ErrBadConfig, storageConfig.GCDelay)
	}

	if storageConfig.GCInterval < 0 {
		logger.Error().Err(zerr.ErrBadConfig).Dur("interval", storageConfig.GCInterval).
			Msg("invalid garbage-collect interval specified")

		return fmt.Errorf("%w: invalid garbage-collect interval specified %s",
			zerr.ErrBadConfig, storageConfig.GCInterval)
	}

	if !storageConfig.GC {
		if storageConfig.GCDelay != 0 {
			logger.Warn().Err(zerr.ErrBadConfig).
				Msg("garbage-collect delay specified without enabling garbage-collect, will be ignored")
		}

		if storageConfig.GCInterval != 0 {
			logger.Warn().Err(zerr.ErrBadConfig).
				Msg("periodic garbage-collect interval specified without enabling garbage-collect, will be ignored")
		}
	}

	if err := validateGCRules(storageConfig.Retention, logger); err != nil {
		return err
	}

	// subpaths
	for name, subPath := range storageConfig.SubPaths {
		if subPath.GC && subPath.GCDelay <= 0 {
			logger.Error().Err(zerr.ErrBadConfig).
				Str("subPath", name).
				Interface("gcDelay", subPath.GCDelay).
				Msg("invalid GC delay configuration - cannot be negative or zero")

			return fmt.Errorf("%w: invalid GC delay configuration - cannot be negative or zero: %s",
				zerr.ErrBadConfig, subPath.GCDelay)
		}

		if err := validateGCRules(subPath.Retention, logger); err != nil {
			return err
		}
	}

	return nil
}

func validateGCRules(retention config.ImageRetention, logger zlog.Logger) error {
	for _, policy := range retention.Policies {
		for _, pattern := range policy.Repositories {
			if ok := glob.ValidatePattern(pattern); !ok {
				logger.Error().Err(glob.ErrBadPattern).Str("pattern", pattern).
					Msg("retention repo glob pattern could not be compiled")

				return fmt.Errorf("%w: retention repo glob pattern could not be compiled: %s",
					zerr.ErrBadConfig, pattern)
			}
		}

		for _, tagRule := range policy.KeepTags {
			for _, regex := range tagRule.Patterns {
				_, err := regexp.Compile(regex)
				if err != nil {
					logger.Error().Err(glob.ErrBadPattern).Str("regex", regex).
						Msg("retention tag regex could not be compiled")

					return fmt.Errorf("%w: retention tag regex could not be compiled: %s",
						zerr.ErrBadConfig, regex)
				}
			}
		}
	}

	return nil
}

func validateSync(config *config.Config, logger zlog.Logger) error {
	// check glob patterns in sync config are compilable
	extensionsConfig := config.CopyExtensionsConfig()
	// can't check with IsSyncEnabled(), because it can't test invalid sync configs
	if extensionsConfig != nil && extensionsConfig.Sync != nil && len(extensionsConfig.Sync.Registries) > 0 {
		for regID, regCfg := range extensionsConfig.Sync.Registries {
			// check retry options are configured for sync
			if regCfg.MaxRetries != nil && regCfg.RetryDelay == nil {
				msg := "retryDelay is required when using maxRetries"
				logger.Error().Err(zerr.ErrBadConfig).Int("id", regID).Interface("extensions.sync.registries[id]",
					extensionsConfig.Sync.Registries[regID]).Msg(msg)

				return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
			}

			// check preserveDigest without compat
			if regCfg.PreserveDigest && !config.IsCompatEnabled() {
				msg := "can not use PreserveDigest option without enabling http.Compat"
				logger.Error().Err(zerr.ErrBadConfig).Int("id", regID).Interface("extensions.sync.registries[id]",
					extensionsConfig.Sync.Registries[regID]).Msg(msg)

				return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
			}

			if regCfg.Content != nil {
				for _, content := range regCfg.Content {
					ok := glob.ValidatePattern(content.Prefix)
					if !ok {
						msg := "sync prefix could not be compiled"
						logger.Error().Err(glob.ErrBadPattern).Str("prefix", content.Prefix).Msg(msg)

						return fmt.Errorf("%w: %s: %s", zerr.ErrBadConfig, msg, content.Prefix)
					}

					if content.Tags != nil && content.Tags.Regex != nil {
						_, err := regexp.Compile(*content.Tags.Regex)
						if err != nil {
							msg := "sync content regex could not be compiled"
							logger.Error().Err(glob.ErrBadPattern).Str("regex", *content.Tags.Regex).Msg(msg)

							return fmt.Errorf("%w: %s: %s", zerr.ErrBadConfig, msg, *content.Tags.Regex)
						}
					}

					if content.Tags != nil && content.Tags.ExcludeRegex != nil {
						_, err := regexp.Compile(*content.Tags.ExcludeRegex)
						if err != nil {
							msg := "sync content excludeRegex could not be compiled"
							logger.Error().Err(glob.ErrBadPattern).Str("excludeRegex", *content.Tags.ExcludeRegex).Msg(msg)

							return fmt.Errorf("%w: %s: %s", zerr.ErrBadConfig, msg, *content.Tags.ExcludeRegex)
						}
					}

					if content.StripPrefix && !strings.Contains(content.Prefix, "/*") && content.Destination == "/" {
						msg := "can not use stripPrefix true and destination '/' without using glob patterns in prefix"
						logger.Error().Err(zerr.ErrBadConfig).
							Interface("sync content", content).Str("component", "sync").Msg(msg)

						return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
					}

					// check sync config doesn't overlap with retention config
					validateRetentionSyncOverlaps(config, content, regCfg.URLs, logger)
				}
			}
		}
	}

	return nil
}

func validateClusterConfig(config *config.Config, logger zlog.Logger) error {
	clusterConfig := config.CopyClusterConfig()
	if clusterConfig != nil {
		if len(clusterConfig.Members) == 0 {
			msg := "cannot have 0 members in a scale out cluster"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}

		// the allowed length is 16 as the siphash requires a 128 bit key.
		// that translates to 16 characters * 8 bits each.
		allowedHashKeyLength := 16
		if len(clusterConfig.HashKey) != allowedHashKeyLength {
			msg := fmt.Sprintf("hashKey for scale out cluster must have %d characters", allowedHashKeyLength)
			logger.Error().Err(zerr.ErrBadConfig).
				Str("hashkey", clusterConfig.HashKey).
				Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}
	}

	return nil
}
