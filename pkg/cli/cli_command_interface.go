package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/plugins"
	cliPlugin "zotregistry.io/zot/pkg/plugins/cli"
)

type Command interface {
	GetCommand() *cobra.Command
}

// cliCommandManager handles the implementation of CLICommand.
// It implements InterfaceManager interface.
var cliCommandManager = cliManager{
	cliCommandImplementations: map[string]plugins.Plugin{},
}

// Object that implements CLICommand and calls on the remote plugin using
// the gRPC client.
type CommandImpl struct {
	name    string
	options plugins.Options
	client  cliPlugin.CLICommandClient
	Log     log.Logger
}

func (cci CommandImpl) Command() *cobra.Command {
	use, err := getField(cci.options["use"])
	if err != nil {
		cci.Log.Err(err).Msgf("CLI plugin config for %v needs to provide 'use' in options field", cci.name)
		panic(err)
	}

	short, err := getField(cci.options["short"])
	if err != nil {
		cci.Log.Info().Msgf("No short description provided for %v CLI plugin", cci.name)
	}

	long, err := getField(cci.options["long"])
	if err != nil {
		cci.Log.Info().Msgf("No long description provided for %v CLI plugin", cci.name)
	}

	return &cobra.Command{
		Use:     use,
		Aliases: []string{},
		Short:   short,
		Long:    long,
		Run: func(cmd *cobra.Command, args []string) {
			response, err := cci.client.Command(
				context.Background(),
				&cliPlugin.CLIArgs{
					Args: args,
				})
			if err != nil {
				fmt.Println(err.Error())
			}

			fmt.Println(response.GetMessage())
		},
	}
}

func getField(option interface{}) (string, error) {
	if option == nil {
		return "", zerr.ErrBadConfig
	}

	f, ok := option.(string)
	if !ok {
		return "", zerr.ErrBadConfig
	}

	return f, nil
}

type cliBuilder struct{}

func (clib cliBuilder) Build(name, addr, port string, options plugins.Options) plugins.Plugin {
	address := fmt.Sprintf("%s:%s", addr, port)

	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println("Can't connect")
	}

	c := cliPlugin.NewCLICommandClient(conn)

	return CommandImpl{name: name, client: c, options: options}
}

type cliManager struct {
	cliCommandImplementations map[string]plugins.Plugin
}

func (clm cliManager) RegisterImplementation(implName string, plugin interface{}) error {
	if _, ok := clm.cliCommandImplementations[implName]; ok {
		return zerr.ErrImplementationConflict
	}

	clm.cliCommandImplementations[implName] = plugin

	return nil
}

func (clm cliManager) AllPlugins() map[string]plugins.Plugin {
	return clm.cliCommandImplementations
}

func init() {
	plugins.Manager().RegisterInterface("CLICommand", cliCommandManager, cliBuilder{})
}
