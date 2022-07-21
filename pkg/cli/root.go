package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"

	distspec "github.com/opencontainers/distribution-spec/specs-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
)

func newServeCmd() *cobra.Command {
	// "serve"
	serveCmd := &cobra.Command{
		Use:     "serve <config>",
		Aliases: []string{"serve"},
		Short:   "`serve` stores and distributes OCI images",
		Long:    "`serve` stores and distributes OCI images",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				hotReloader, err := NewHotReloader(args[0])
				if err != nil {
					panic(err)
				}

				hotReloader.Start()
			} else {
				if err := cmd.Usage(); err != nil {
					panic(err)
				}

				return
			}
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
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				if err := config.LoadFromFile(args[0], conf); err != nil {
					panic(err)
				}
			} else {
				if err := cmd.Usage(); err != nil {
					panic(err)
				}

				return
			}

			// checking if the server is  already running
			ok := isServerRunning(conf.HTTP.Address, conf.HTTP.Port)
			if ok {
				log.Warn().Msg("The server is running, in order to perform the scrub command the server should be shut down")
				panic("Error: server is running")
			} else {
				// server is down
				ctlr := api.NewController(conf)
				ctlr.Metrics = monitoring.NewMetricsServer(false, ctlr.Log)

				if err := ctlr.InitImageStore(); err != nil {
					panic(err)
				}

				result, err := ctlr.StoreController.CheckAllBlobsIntegrity()
				if err != nil {
					panic(err)
				}

				result.PrintScrubResults(cmd.OutOrStdout())
			}
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
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				if err := config.LoadFromFile(args[0], conf); err != nil {
					log.Error().Err(err).Str("path", args[0]).Msgf("invalid config file %s", args[0])

					panic(err)
				}

				log.Info().Msgf("config file %s is valid", args[0])
			}
		},
	}

	return verifyCmd
}

// "zot" - registry server.
func NewServerRootCmd() *cobra.Command {
	showVersion := false
	conf := config.New()

	rootCmd := &cobra.Command{
		Use:   "zot",
		Short: "`zot`",
		Long:  "`zot`",
		Run: func(cmd *cobra.Command, args []string) {
			if showVersion {
				log.Info().Str("distribution-spec", distspec.Version).Str("commit", config.Commit).
					Str("binary-type", config.BinaryType).Str("go version", config.GoVersion).Msg("version")
			} else {
				_ = cmd.Usage()
				cmd.SilenceErrors = false
			}
		},
	}

	// "serve"
	rootCmd.AddCommand(newServeCmd())
	// "verify"
	rootCmd.AddCommand(newVerifyCmd(conf))
	// "scrub"
	rootCmd.AddCommand(newScrubCmd(conf))
	// "version"
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "show the version and exit")

	return rootCmd
}

// "zli" - client-side cli.
func NewCliRootCmd() *cobra.Command {
	showVersion := false

	rootCmd := &cobra.Command{
		Use:   "zli",
		Short: "`zli`",
		Long:  "`zli`",
		Run: func(cmd *cobra.Command, args []string) {
			if showVersion {
				log.Info().Str("distribution-spec", distspec.Version).Str("commit", config.Commit).
					Str("binary-type", config.BinaryType).Str("go version", config.GoVersion).Msg("version")
			} else {
				_ = cmd.Usage()
				cmd.SilenceErrors = false
			}
		},
	}

	// additional cmds
	enableCli(rootCmd)
	// "version"
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "show the version and exit")

	return rootCmd
}

func isServerRunning(address, port string) bool {
	// checking if the server is  already running
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodGet,
		fmt.Sprintf("http://%s/v2", net.JoinHostPort(address, port)),
		nil)
	if err != nil {
		log.Error().Err(err).Msg("unable to create a new http request")
		panic(err)
	}

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}

	response.Body.Close()

	return true
}
