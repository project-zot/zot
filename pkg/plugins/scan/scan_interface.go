package scan

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"zotregistry.io/zot/pkg/plugins"
)

type VulnScanner interface {
	ScanImage(ctx *cli.Context, image string) (*ScanReport, error)
}

// RPCScanner Implements VulnScanner and calls on the gRPC client for
// the needed logic (that takes place remotely).
type RPCScanner struct {
	name    string
	options plugins.Options
	client  ScanClient
}

func (rs RPCScanner) ScanImage(ctx *cli.Context, image string) (*ScanReport, error) {
	url, ok := rs.options["zot-addr"].(string)
	if !ok {
		return &ScanReport{}, nil // Needs to return error.
	}

	response, err := rs.client.Scan(context.Background(),
		&ScanRequest{
			Image: image,
			Registry: &Registry{
				Url: url,
			},
		})

	return response.Report, err
}

type RPCScanBuilder struct{}

func (sb RPCScanBuilder) Build(name, addr, port string, options plugins.Options) plugins.Plugin {
	address := fmt.Sprintf("%s:%s", addr, port)

	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println("Can't connect")
	}

	c := NewScanClient(conn)

	return RPCScanner{name: name, client: c, options: options}
}

// This manager follows the "driver" pattern:
// https://docs.openstack.org/stevedore/latest/user/essays/pycon2013.html
// https://docs.openstack.org/stevedore/latest/user/patterns_loading.html
type RPCScanManager struct {
	Impl *struct {
		Name            string
		VulnScannerImpl plugins.Plugin
	}
}

func (rsm RPCScanManager) RegisterImplementation(name string, plugin interface{}) error {
	rsm.Impl.Name = name
	rsm.Impl.VulnScannerImpl = plugin

	return nil
}

func (rsm RPCScanManager) AllPlugins() map[string]plugins.Plugin {
	return map[string]plugins.Plugin{
		rsm.Impl.Name: rsm.Impl.VulnScannerImpl,
	}
}

func (rsm RPCScanManager) GetImpl(name string) plugins.Plugin {
	if rsm.Impl.Name != name && name != "default" {
		return nil
	}

	Impl := rsm.Impl.VulnScannerImpl
	if Impl == nil {
		return nil
	}

	im, ok := Impl.(VulnScanner)
	if !ok {
		return nil
	}

	return im
}

func (rsm RPCScanManager) GetImplName() string {
	Impl := rsm.Impl.VulnScannerImpl
	if Impl == nil {
		return ""
	}

	return rsm.Impl.Name
}
