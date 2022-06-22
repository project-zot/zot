package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	plugins "zotregistry.io/zot/pkg/plugins/common"
)

type Command interface {
	GetCommand() *cobra.Command
}

// cliCommandManager handles the implementation of CLICommand.
// It implements InterfaceManager interface.

// Object that implements CLICommand and calls on the remote plugin using
// the gRPC client.
type BaseCommand struct {
	Name    string
	Options plugins.Options
	Client  CLICommandClient
	Log     log.Logger
}

func (cci BaseCommand) GetCommand() *cobra.Command {
	use, err := getField(cci.Options["use"])
	if err != nil {
		cci.Log.Err(err).Msgf("CLI plugin config for %v needs to provide 'use' in options field", cci.Name)
		panic(err)
	}

	short, err := getField(cci.Options["short"])
	if err != nil {
		cci.Log.Info().Msgf("No short description provided for %v CLI plugin", cci.Name)
	}

	long, err := getField(cci.Options["long"])
	if err != nil {
		cci.Log.Info().Msgf("No long description provided for %v CLI plugin", cci.Name)
	}

	return &cobra.Command{
		Use:     use,
		Aliases: []string{},
		Short:   short,
		Long:    long,
		Run: func(cmd *cobra.Command, args []string) {
			response, err := cci.Client.Command(
				context.Background(),
				&CLIArgs{
					Args: args,
				})
			if err != nil {
				panic(err)
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

type Builder struct{}

func (clib Builder) Build(name, addr, port string, options plugins.Options,
) (plugins.Plugin, error) {
	address := fmt.Sprintf("%s:%s", addr, port)

	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println("Can't dial")

		return nil, err
	}

	c := NewCLICommandClient(conn)

	return BaseCommand{Name: name, Client: c, Options: options}, nil
}

type Manager struct {
	Implementations map[string]plugins.Plugin
}

func (clm Manager) RegisterImplementation(implName string, plugin interface{}) error {
	if _, ok := clm.Implementations[implName]; ok {
		return zerr.ErrImplNameCollision
	}

	clm.Implementations[implName] = plugin

	return nil
}

func (clm Manager) AllPlugins() map[string]plugins.Plugin {
	return clm.Implementations
}

func (clm Manager) GetImpl(name string) plugins.Plugin {
	return clm.Implementations[name]
}
