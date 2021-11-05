package performance

import (
	"encoding/json"
	"io/ioutil"

	// nolint: golint,stylecheck
	. "github.com/onsi/gomega"
)

type MeasurementConfig struct {
	SingleImagePushTime         int `json:"singleImagePushTime"`
	ParallelPushTime            int `json:"parallelPushTime"`
	SingleImageParallelPushTime int `json:"SingleImageParallelPushTime"`
	Times                       int `json:"times"`
}

func LoadMeasurementConfig(input string) *MeasurementConfig {
	configData, err := ioutil.ReadFile(input)
	Expect(err).ToNot(HaveOccurred(),
		"Failed to read measurement config file")
	Expect(configData).ToNot(BeEmpty(),
		"The measurement config file should not be empty")

	config := &MeasurementConfig{}
	Expect(json.Unmarshal(configData, config)).To(Succeed(),
		"Failed to convert the measurement config file")

	return config
}
