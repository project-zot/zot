package server

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/spf13/cobra"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	zlog "zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/scheduler"
	"zotregistry.dev/zot/pkg/storage"
)

func newRetentionCheckCmd(conf *config.Config) *cobra.Command {
	// "retention-check"
	retentionCheckCmd := &cobra.Command{
		Use:   "retention-check <config>",
		Short: "`retention-check` runs garbage collection and retention tasks",
		Long: "`retention-check` runs garbage collection and retention tasks based on the provided configuration.\n\n" +
			"WARNING: If retention settings are enabled in the config, the server metadata database needs to be accessed, " +
			"which means the zot server must be stopped before running this command.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Use stdout by default, or the specified log file
			logFile, _ := cmd.PersistentFlags().GetString("log-file")
			logOutput := ""
			if logFile != "" {
				logOutput = logFile
			}
			logger := zlog.NewLogger("info", logOutput)

			if len(args) > 0 {
				if err := LoadConfiguration(conf, args[0]); err != nil {
					return err
				}
			}

			// Do not show usage on errors which are not related to command line arguments
			cmd.SilenceUsage = true

			// Check if GC is enabled in config
			if !conf.Storage.GC {
				logger.Error().Msg("Garbage collection is disabled in config - retention-check requires GC to be enabled")

				return zerr.ErrBadConfig
			}

			// Enable retention dry-run mode
			conf.Storage.Retention.DryRun = true

			// Override GC interval if specified
			gcInterval, _ := cmd.PersistentFlags().GetDuration("gc-interval")
			if gcInterval > 0 {
				conf.Storage.GCInterval = gcInterval
			}

			// Process subpaths for both retention dry-run and GC interval override
			if conf.Storage.SubPaths != nil {
				for route, storageConfig := range conf.Storage.SubPaths {
					storageConfig.Retention.DryRun = true
					if gcInterval > 0 {
						storageConfig.GCInterval = gcInterval
					}
					conf.Storage.SubPaths[route] = storageConfig
				}
			}

			// Initialize store controller
			storeController, err := storage.New(conf, nil, nil, logger, nil)
			if err != nil {
				logger.Error().Err(err).Msg("Failed to initialize store controller")

				return err
			}

			// Initialize MetaDB if retention is enabled
			var metaDB mTypes.MetaDB
			if conf.IsRetentionEnabled() {
				logger.Warn().Msg("Retention settings are enabled - the zot server must be stopped to access the metadata database")

				if err := checkServerRunning(conf, logger); err != nil {
					return err
				}

				driver, err := meta.New(conf.Storage.StorageConfig, logger)
				if err != nil {
					logger.Error().Err(err).Msg("failed to initialize metadata database")

					return err
				}

				err = meta.ParseStorage(driver, storeController, logger)
				if err != nil {
					logger.Error().Err(err).Msg("failed to parse storage")

					return err
				}

				metaDB = driver
			} else {
				logger.Warn().Msg("Retention settings are disabled - garbage collection will run without retention policies")
			}

			// Initialize scheduler
			taskScheduler := scheduler.NewScheduler(conf, nil, logger)
			taskScheduler.RunScheduler()

			// Ask for user confirmation before proceeding
			logger.Warn().Msg("The jobs will only show which tags, manifests and referrers would be removed (dry-run), " +
				"but will actually delete unreferenced blobs from storage")
			logger.Info().Msg("Do you want to proceed? (y/N): ")

			var response string
			if _, err := fmt.Scanln(&response); err != nil {
				logger.Error().Err(err).Msg("failed to read user input")

				return err
			}

			if response != "y" && response != "Y" {
				logger.Info().Msg("operation cancelled by user")

				return nil
			}

			logger.Info().Msg("garbage collection and retention tasks will be submitted to the scheduler")

			// Run GC and retention tasks
			api.RunGCTasks(conf, storeController, metaDB, taskScheduler, logger, nil)

			// Keep the process running to allow background tasks to complete
			// Wait for interrupt signal to gracefully shutdown
			select {
			case <-cmd.Context().Done():
				logger.Info().Msg("received shutdown signal, stopping garbage collection tasks")
				taskScheduler.Shutdown()
			}

			return nil
		},
	}

	retentionCheckCmd.PersistentFlags().StringP("log-file", "l", "", "log file location (default: stdout)")
	retentionCheckCmd.PersistentFlags().DurationP("gc-interval", "i", 0,
		"override GC interval (default: use config value)")

	return retentionCheckCmd
}

// checkServerRunning checks if a Zot server is already running on the configured address/port.
func checkServerRunning(conf *config.Config, logger zlog.Logger) error {
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
			Msg("server is running, in order to perform the retention-check command the server should be shut down")

		return zerr.ErrServerIsRunning
	}

	return nil
}
