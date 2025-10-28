package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
)

func newVerifyFeatureRetentionCmd(conf *config.Config) *cobra.Command {
	// "verify-feature retention"
	retentionCheckCmd := &cobra.Command{
		Use:   "retention <config>",
		Short: "`verify-feature retention` runs garbage collection and retention tasks",
		Long: "`verify-feature retention` runs garbage collection and retention tasks " +
			"based on the provided configuration.\n\n" +
			"WARNING: If retention settings are enabled in the config, the server metadata database needs to be accessed, " +
			"which means the zot server must be stopped before running this command.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Use stdout by default, or the specified log file
			logFile, err := cmd.PersistentFlags().GetString("log-file")
			if err != nil {
				return fmt.Errorf("failed to get log-file flag: %w", err)
			}

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
				logger.Error().Msgf("failed to run verify-feature retention, garbage collection is disabled in config")

				return fmt.Errorf("%w: %s", zerr.ErrBadConfig, "verify-feature retention requires GC to be enabled")
			}

			// Set short delay for verify-feature retention command
			conf.Storage.GCMaxSchedulerDelay = 5 * time.Millisecond

			// Override GC interval if specified
			gcInterval, err := cmd.PersistentFlags().GetDuration("gc-interval")
			if err != nil {
				return fmt.Errorf("failed to get gc-interval flag: %w", err)
			}

			if gcInterval > 0 {
				conf.Storage.GCInterval = gcInterval
			}

			// Process subpaths for GC interval override
			if conf.Storage.SubPaths != nil {
				for route, storageConfig := range conf.Storage.SubPaths {
					storageConfig.GCMaxSchedulerDelay = 5 * time.Millisecond
					if gcInterval > 0 {
						storageConfig.GCInterval = gcInterval
					}
					conf.Storage.SubPaths[route] = storageConfig
				}
			}

			// Log entire configuration after all overrides
			logger.Info().Interface("params", conf.Sanitize()).
				Msg("configuration settings (after applying overrides)")

			// Check if server is running BEFORE initializing storage (to avoid database lock)
			if !isRemoteCacheEnabled(conf) {
				logger.Warn().Msg("local storage detected - the zot server must be stopped to access the storage database")

				if err := checkServerRunning(conf, logger); err != nil {
					return err
				}
			}

			// Initialize metrics server
			metricsServer := monitoring.NewMetricsServer(false, logger)

			// Initialize store controller
			storeController, err := storage.New(conf, nil, metricsServer, logger, nil)
			if err != nil {
				msg := "failed to initialize store controller"
				logger.Error().Err(err).Msg(msg)

				return fmt.Errorf("%s: %w", msg, err)
			}

			// Initialize MetaDB only if retention policies are configured
			var metaDB mTypes.MetaDB
			if conf.IsRetentionEnabled() {
				// Enable retention dry-run mode only when retention is enabled
				conf.Storage.Retention.DryRun = true

				// Process subpaths for retention dry-run
				if conf.Storage.SubPaths != nil {
					for route, storageConfig := range conf.Storage.SubPaths {
						storageConfig.Retention.DryRun = true
						conf.Storage.SubPaths[route] = storageConfig
					}
				}

				driver, err := meta.New(conf.Storage.StorageConfig, logger)
				if err != nil {
					msg := "failed to initialize metadata database"
					logger.Error().Err(err).Msg(msg)

					return fmt.Errorf("%s: %w", msg, err)
				}

				err = meta.ParseStorage(driver, storeController, logger)
				if err != nil {
					msg := "failed to parse storage"
					logger.Error().Err(err).Msg(msg)

					return fmt.Errorf("%s: %w", msg, err)
				}

				metaDB = driver
				logger.Info().Msg("retention policies are configured - retention rules will be applied")
			} else {
				metaDB = nil
				logger.Info().Msg("no retention policies are configured - garbage collection will run with default settings")
			}

			// Initialize scheduler
			taskScheduler := scheduler.NewScheduler(conf, metricsServer, logger)
			taskScheduler.RunScheduler()
			defer taskScheduler.Shutdown()

			logger.Info().Msg("garbage collection and retention tasks will be submitted to the scheduler")

			// Run GC and retention tasks
			api.RunGCTasks(conf, storeController, metaDB, taskScheduler, logger, nil)

			// Wait for tasks to complete with optional timeout
			timeout, err := cmd.PersistentFlags().GetDuration("timeout")
			if err != nil {
				return fmt.Errorf("failed to get timeout flag: %w", err)
			}

			var waitCtx context.Context
			var cancel context.CancelFunc

			if timeout > 0 {
				logger.Info().Dur("timeout", timeout).Msg("waiting for garbage collection tasks to complete...")
				waitCtx, cancel = context.WithTimeout(context.Background(), timeout)
			} else {
				logger.Info().Msg("waiting for garbage collection tasks to complete indefinitely " +
					"(can be interrupted by SIGINT/SIGTERM)...")
				waitCtx, cancel = context.WithCancel(cmd.Context())
			}
			defer cancel()

			// Set up signal handling for graceful shutdown
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

			// Wait for either context cancellation or signal
			select {
			case <-waitCtx.Done():
				logger.Info().Msg("retention check completed successfully")
			case sig := <-sigChan:
				logger.Info().Str("signal", sig.String()).Msg("received interrupt signal, stopping retention check")
				logger.Info().Msg("retention check stopped gracefully")
			}

			return nil
		},
	}

	retentionCheckCmd.PersistentFlags().StringP("log-file", "l", "", "log file location (default: stdout)")
	retentionCheckCmd.PersistentFlags().DurationP("gc-interval", "i", 0,
		"override GC interval (default: use config value)")
	retentionCheckCmd.PersistentFlags().DurationP("timeout", "t", 0,
		"timeout for waiting for tasks to complete (default: wait indefinitely)")

	return retentionCheckCmd
}

// checkServerRunning checks if a Zot server is already running on the configured address/port.
func checkServerRunning(conf *config.Config, logger zlog.Logger) error {
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodGet,
		fmt.Sprintf("http://%s/v2", net.JoinHostPort(conf.HTTP.Address, conf.HTTP.Port)),
		nil)
	if err != nil {
		msg := "failed to create http request"
		logger.Error().Err(err).Msg(msg)

		return fmt.Errorf("%s: %w", msg, err)
	}

	response, err := http.DefaultClient.Do(req)
	if err == nil {
		response.Body.Close()
		logger.Warn().Err(zerr.ErrServerIsRunning).
			Msg("server is running, in order to perform the verify-feature retention command the server should be shut down")

		return zerr.ErrServerIsRunning
	}

	return nil
}

// isRemoteCacheEnabled checks if the remote cache is enabled for the global and subpaths storage configs.
func isRemoteCacheEnabled(conf *config.Config) bool {
	if conf == nil || !conf.Storage.RemoteCache {
		return false
	}

	for _, subStorageConfig := range conf.Storage.SubPaths {
		if !subStorageConfig.RemoteCache {
			return false
		}
	}

	return true
}
