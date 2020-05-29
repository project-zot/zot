package cveinfo

import (
	"time"

	"github.com/anuvu/zot/pkg/log"
	integration "github.com/aquasecurity/trivy/integration"
	config "github.com/aquasecurity/trivy/integration/config"
	"github.com/aquasecurity/trivy/pkg/report"
)

// UpdateCVEDb ...
func UpdateCVEDb(dbDir string, log log.Logger, interval time.Duration, isTest bool) error {
	config, err := config.NewDbConfig(dbDir)
	if err != nil {
		log.Error().Err(err).Msg("Unable to get config")
		return err
	}

	for {
		err = integration.RunDb(config.TrivyConfig)
		if err != nil {
			log.Error().Err(err).Msg("Unable to update DB ")
			return err
		}

		if isTest {
			return nil
		}

		time.Sleep(interval * time.Hour)
	}
}

func NewTrivyConfig(dir string) (*config.Config, error) {
	return config.NewConfig(dir)
}

func ScanImage(config *config.Config) (report.Results, error) {
	return integration.Run(config.TrivyConfig)
}
