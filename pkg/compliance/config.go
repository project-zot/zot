package compliance

type Config struct {
	Address string
	Port    string
	Version string
}

func NewConfig() *Config {
	return &Config{}
}
