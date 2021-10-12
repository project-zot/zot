// +build minimal

package api

// We export below types in order for cli package to be able to read it from configuration file.
type LogConfig struct {
	Level  string
	Output string
}

type MetricsConfig struct {
	Path string
}

type ServerConfig struct {
	Protocol string
	Host     string
	Port     string
}

type ExporterConfig struct {
	Port    string
	Log     *LogConfig
	Metrics *MetricsConfig
}

type Config struct {
	ZotServer   ServerConfig
	ZotExporter ExporterConfig
}

func DefaultConfig() *Config {
	return &Config{
		ZotServer:   ServerConfig{Protocol: "http", Host: "localhost", Port: "8080"},
		ZotExporter: ExporterConfig{Port: "8081", Log: &LogConfig{Level: "debug"}, Metrics: &MetricsConfig{Path: "/metrics"}},
	}
}
