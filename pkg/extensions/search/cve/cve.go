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
		err = integration.RunTrivyDb(config.TrivyConfig)
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
	return integration.ScanTrivyImage(config.TrivyConfig)
}

/*func (cve CveInfo) ListAllTags(rootDir string, fileName string) ([]string, error) {
	dir := path.Join(rootDir, fileName)
	if !dirExists(dir) {
		cve.Log.Error().Msg("Image Directory not exists")

		return nil, errors.ErrRepoIsNotDir
	}

	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))

	if err != nil {
		if os.IsNotExist(err) {
			cve.Log.Error().Err(err).Msg("Index.json does not exist")

			return nil, err
		}

		cve.Log.Error().Err(err).Msg("Unable to open index.json")

		return nil, err
	}

	var index ispec.Index

	if err := json.Unmarshal(buf, &index); err != nil {
		cve.Log.Error().Err(err).Msg("Unable to marshal index.json file")

		return nil, err
	}

	tags := make([]string, 0)

	for _, m := range index.Manifests {
		v, ok := m.Annotations[ispec.AnnotationRefName]
		if ok {
			tags = append(tags, v)
		}
	}

	return tags, nil
}

func dirExists(d string) bool {
	fi, err := os.Stat(d)
	if err != nil && os.IsNotExist(err) {
		return false
	}

	return fi.IsDir()
}*/
