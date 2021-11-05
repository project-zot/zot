package perf

import (
	"encoding/json"
	"io/ioutil"
	"log"
)

type ServerConfig struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
	Repo     string `json:"repo"`
}

func LoadServerConfig(input string) *ServerConfig {
	config := &ServerConfig{}
	configData, err := ioutil.ReadFile(input)

	if err != nil {
		log.Fatalln(err)
	}

	if configData == nil {
		log.Fatalln(err)
	}

	if err := json.Unmarshal(configData, config); err != nil {
		log.Fatalln(err)
	}

	return config
}
