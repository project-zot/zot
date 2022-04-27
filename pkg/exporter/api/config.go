//go:build !metrics
// +build !metrics

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
	Server   ServerConfig
	Exporter ExporterConfig
}

func DefaultConfig() *Config {
	return &Config{
		Server:   ServerConfig{Protocol: "http", Host: "localhost", Port: "8080"},
		Exporter: ExporterConfig{Port: "8081", Log: &LogConfig{Level: "debug"}, Metrics: &MetricsConfig{Path: "/metrics"}},
	}
}
