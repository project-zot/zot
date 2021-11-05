package performance

import (
	"encoding/json"
	"io/ioutil"

	// nolint: golint,stylecheck
	. "github.com/onsi/gomega"
)

type ServerConfig struct {
	Address   string `json:"address"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Repo      string `json:"repo"`
	TlsVerify bool   `json:"tlsVerify"`
}

func LoadServerConfig(input string) *ServerConfig {
	configData, err := ioutil.ReadFile(input)
	Expect(err).ToNot(HaveOccurred(),
		"Failed to read config file")
	Expect(configData).ToNot(BeEmpty(),
		"The server config file should not be empty")

	config := &ServerConfig{}
	Expect(json.Unmarshal(configData, config)).To(Succeed(),
		"Failed to convert the server config file")

	return config
}
