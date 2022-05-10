package common

type Config struct {
	Name              string
	IntegrationPoints []IntegrationPoint
}

type IntegrationPoint struct {
	Interface      string
	GrpcConnection GrpcConnection
	Options        Options
}

type Options map[string]interface{}

type GrpcConnection struct {
	Addr string
	Port string
}
