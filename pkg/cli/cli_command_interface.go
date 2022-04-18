package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/plugins"
	cliPlugin "zotregistry.io/zot/pkg/plugins/cli"
)

// interface
type CLICommand interface {
	Command() *cobra.Command
}

// cliCommandManager handles the implementation of CLICommand.
// It implements InterfaceManager interface
var cliCommandManager cliManager = cliManager{
	cliCommandImplementations: map[string]plugins.Plugin{},
}

// Object that implements CLICommand and calls on the remote plugin using
// the gRPC client.
type CLICommandImpl struct {
	options plugins.Options
	client  cliPlugin.CLICommandClient
}

type cliBuilder struct{}

func (clib cliBuilder) Build(addr, port string, options plugins.Options) plugins.Plugin {
	address := fmt.Sprintf("%s:%s", addr, port)
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println("Can't connect")
	}

	c := cliPlugin.NewCLICommandClient(conn)

	return CLICommandImpl{client: c, options: options}
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

func (cci CLICommandImpl) Command() *cobra.Command {
	use := cci.options["use"]
	short := cci.options["short"]
	long := cci.options["long"]

	return &cobra.Command{
		Use:     use.(string),
		Aliases: []string{},
		Short:   short.(string),
		Long:    long.(string),
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

func init() {
	plugins.PluginManager.RegisterInterface("CLICommand", cliCommandManager, cliBuilder{})
}
