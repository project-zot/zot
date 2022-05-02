package cveinfo

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"zotregistry.io/zot/pkg/plugins"
	scanPlugin "zotregistry.io/zot/pkg/plugins/scan"
)

type VulnScanner interface {
	ScanImage(ctx *cli.Context) (*scanPlugin.ScanReport, error)
}

// RPCScanner implements VulnScanner and calls on the gRPC client for
// the needed logic (that takes place remotely).
type RPCScanner struct {
	name    string
	options plugins.Options
	client  scanPlugin.ScanClient
}

func (rs RPCScanner) ScanImage(ctx *cli.Context) (*scanPlugin.ScanReport, error) {
	image, ok := ctx.Context.Value("image").(string)
	if !ok {
		return &scanPlugin.ScanReport{}, nil // TODO return error.
	}

	url, ok := rs.options["zot-addr"].(string)
	if !ok {
		return &scanPlugin.ScanReport{}, nil // TODO return error.
	}

	response, err := rs.client.Scan(context.Background(),
		&scanPlugin.ScanRequest{
			Image: image,
			Registry: &scanPlugin.Registry{
				Url: url,
			},
		})

	return response.Report, err
}

type rpcScanBuilder struct{}

func (sb rpcScanBuilder) Build(name, addr, port string, options plugins.Options) plugins.Plugin {
	address := fmt.Sprintf("%s:%s", addr, port)

	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println("Can't connect")
	}

	c := scanPlugin.NewScanClient(conn)

	return RPCScanner{name: name, client: c, options: options}
}

// This manager follows the "driver" pattern:
// https://docs.openstack.org/stevedore/latest/user/essays/pycon2013.html#:~:text=%E2%80%9CDrivers%E2%80%9D%20are%20loaded%20one%20at%20a%20time%2C%20and%20used%20directly.
// https://docs.openstack.org/stevedore/latest/user/patterns_loading.html
type rpcScanManager struct {
	impl *struct {
		Name            string
		VulnScannerImpl plugins.Plugin
	}
}

var scanManager = rpcScanManager{
	impl: &struct {
		Name            string
		VulnScannerImpl plugins.Plugin
	}{},
}

func (rsm rpcScanManager) RegisterImplementation(name string, plugin interface{}) error {
	rsm.impl.Name = name
	rsm.impl.VulnScannerImpl = plugin

	return nil
}

func (rsm rpcScanManager) AllPlugins() map[string]plugins.Plugin {
	return map[string]plugins.Plugin{
		rsm.impl.Name: rsm.impl.VulnScannerImpl,
	}
}

func (rsm rpcScanManager) GetImpl() VulnScanner {
	impl := rsm.impl.VulnScannerImpl
	if impl == nil {
		return nil
	}

	im, ok := impl.(VulnScanner)
	if !ok {
		return nil
	}

	return im
}

func (rsm rpcScanManager) GetImplName() string {
	impl := rsm.impl.VulnScannerImpl
	if impl == nil {
		return ""
	}

	return rsm.impl.Name
}

func init() {
	plugins.Manager().RegisterInterface("VulnScanner", scanManager, rpcScanBuilder{})
}
