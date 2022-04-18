package cveinfo

import (
	"context"
	"fmt"

	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"zotregistry.io/zot/pkg/extensions/search/cve/convert"
	"zotregistry.io/zot/pkg/plugins"
	scanPlugin "zotregistry.io/zot/pkg/plugins/scan"
)

// interface
type VulnScanner interface {
	ScanImage(ctx *cli.Context) (report.Report, error)
}

// struct that implements the interface and calls on the client for operations
type RpcScanner struct {
	options plugins.Options
	client  scanPlugin.ScanClient
}

func (rs RpcScanner) ScanImage(ctx *cli.Context) (report.Report, error) {
	response, err := rs.client.Scan(context.Background(),
		&scanPlugin.ScanRequest{
			ImageName:    ctx.Context.Value("image").(string),
			ServerAdress: rs.options["zot-addr"].(string),
		})

	results := convert.FromRPCResults(response.Results)

	return report.Report{
		Results: results,
	}, err
}

var scanManager rpcScanManager = rpcScanManager{
	impl: &struct {
		Name            string
		VulnScannerImpl plugins.Plugin
	}{},
}

type rpcScanBuilder struct{}

func (sb rpcScanBuilder) Build(addr, port string, options plugins.Options) plugins.Plugin {
	address := fmt.Sprintf("%s:%s", addr, port)
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println("Can't connect")
	}
	c := scanPlugin.NewScanClient(conn)
	return RpcScanner{client: c, options: options}
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
	return rsm.impl.VulnScannerImpl.(VulnScanner)
}

func (rsm rpcScanManager) GetImplName() string {
	return rsm.impl.Name
}

func init() {
	plugins.PluginManager.RegisterInterface("VulnScanner", scanManager, rpcScanBuilder{})
}
