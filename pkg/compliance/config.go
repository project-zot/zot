package compliance

type Config struct {
	Address     string
	Port        string
	Version     string
	StorageInfo []string
	OutputJSON  bool
	Compliance  bool
}

func NewConfig() *Config {
	return &Config{Compliance: true}
}
