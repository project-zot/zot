package compliance

type Config struct {
	Address    string
	Port       string
	Version    string
	OutputJSON bool
}

func NewConfig() *Config {
	return &Config{}
}
