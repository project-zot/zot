package perf

import (
	"encoding/json"
	"io/ioutil"
	"log"
)

type MeasurementConfig struct {
	SingleImagePushTime         int `json:"singleImagePushTime"`
	SingleImagePullTime         int `json:"singleImagePullTime"`
	ParallelPushTime            int `json:"parallelPushTime"`
	SingleImageParallelPushTime int `json:"singleImageParallelPushTime"`
	SingleImageParallelPullTime int `json:"singleImageParallelPullTime"`
	Times                       int `json:"times"`
	ParallelImagesNumber        int `json:"parallelImagesNumber"`
}

func LoadMeasurementConfig(input string) *MeasurementConfig {
	config := &MeasurementConfig{}
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
