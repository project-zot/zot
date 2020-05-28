package cveinfo

import (
	"time"

	"github.com/anuvu/zot/pkg/log"
	integration "github.com/aquasecurity/trivy/integration"
	config "github.com/aquasecurity/trivy/integration/config"
)

// UpdateCVEDb ...
func UpdateCVEDb(dbDir string, log log.Logger, interval time.Duration, readOnly bool) {
	config, err := config.NewDbConfig(dbDir)
	if err != nil {
		log.Error().Err(err).Msg("Unable to get config")
	}

	for {
		err = integration.RunDb(config)
		if err != nil {
			log.Error().Err(err).Msg("Unable to update DB ")
		}

		time.Sleep(interval * time.Hour)
	}
}
