package cli_test

import (
	"context"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"google.golang.org/grpc"
	"zotregistry.io/zot/errors"
	. "zotregistry.io/zot/pkg/plugins/cli"
	"zotregistry.io/zot/pkg/plugins/common"
)

type mockCliClient struct {
	commandFn func(ctx context.Context, in *CLIArgs, opts ...grpc.CallOption) (*CLIResponse, error)
}

func (f *mockCliClient) Command(ctx context.Context, in *CLIArgs, opts ...grpc.CallOption,
) (*CLIResponse, error) {
	if f.commandFn != nil {
		return f.commandFn(ctx, in, opts...)
	}

	return &CLIResponse{}, nil
}
func TestBaseCommand(t *testing.T) {
	Convey("GetCommand, options are absent.", t, func() {
		baseCommand := BaseCommand{
			Name:   "Test",
			Client: &mockCliClient{},
		}

		Convey("All options are absent", func() {
			So(func() { baseCommand.GetCommand() }, ShouldPanic)
		})

		Convey("Only use is present", func() {
			baseCommand.Options = common.Options{
				"use": "testuse",
			}
			cmd := baseCommand.GetCommand()

			So(cmd.Use, ShouldResemble, "testuse")
			So(cmd.Long, ShouldBeBlank)
			So(cmd.Short, ShouldBeBlank)
		})

		Convey("Use options is not string", func() {
			baseCommand.Options = common.Options{
				"use": 100,
			}

			So(func() {
				baseCommand.GetCommand()
			},
				ShouldPanic)
		})
	})

	Convey("Returned command with mock client", t, func() {
		baseCommand := BaseCommand{
			Name: "Test",
			Options: common.Options{
				"use":   "testuse",
				"long":  "testlong",
				"short": "testshort",
			},
		}
		Convey("The client returns an error", func() {
			baseCommand.Client = &mockCliClient{
				commandFn: func(ctx context.Context, in *CLIArgs, opts ...grpc.CallOption) (*CLIResponse, error) {
					return &CLIResponse{}, grpc.ErrServerStopped
				},
			}

			command := baseCommand.GetCommand()

			So(func() { command.Run(command, []string{}) }, ShouldPanic)
		})

		Convey("The client responds with success", func() {
			baseCommand.Client = &mockCliClient{
				commandFn: func(ctx context.Context, in *CLIArgs, opts ...grpc.CallOption) (*CLIResponse, error) {
					return &CLIResponse{
						Message: "This is success",
					}, nil
				},
			}

			command := baseCommand.GetCommand()

			So(func() { command.Run(command, []string{}) }, ShouldNotPanic)
		})
	})
}

func TestCLIBuilder(t *testing.T) {
	Convey("Test CLI Builder", t, func() {
		builder := Builder{}

		Convey("Success build", func() {
			plugin, err := builder.Build(
				"testName",
				"127.0.0.1",
				"9000",
				common.Options{},
			)
			So(err, ShouldBeNil)
			So(plugin, ShouldNotBeNil)

			cliPlugin, ok := plugin.(Command)
			So(ok, ShouldNotBeNil)
			So(cliPlugin, ShouldNotBeNil)
		})
	})
}

func TestCLIImplManager(t *testing.T) {
	Convey("Implementation registration", t, func() {
		cliImplManager := Manager{
			Implementations: map[string]common.Plugin{},
		}

		cliImplManager.RegisterImplementation(
			"TestCliImpl1",
			BaseCommand{},
		)
		cliImplManager.RegisterImplementation(
			"TestCliImpl2",
			BaseCommand{},
		)

		So(len(cliImplManager.AllPlugins()), ShouldEqual, 2)
		So(cliImplManager.GetImpl("TestCliImpl1"), ShouldNotBeNil)
	})

	Convey("Implementation registration name collision", t, func() {
		cliImplManager := Manager{
			Implementations: map[string]common.Plugin{},
		}

		err := cliImplManager.RegisterImplementation(
			"TestCliImpl1",
			BaseCommand{},
		)
		So(err, ShouldBeNil)

		err = cliImplManager.RegisterImplementation(
			"TestCliImpl1",
			BaseCommand{},
		)
		So(err, ShouldEqual, errors.ErrImplNameCollision)
	})
}
