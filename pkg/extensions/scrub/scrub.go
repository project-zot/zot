//go:build scrub
// +build scrub

package scrub

import (
	"fmt"
	"path"

	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

// Scrub Extension for repo...
func RunScrubRepo(imgStore storage.ImageStore, repo string, log log.Logger) error {
	execMsg := fmt.Sprintf("executing scrub to check manifest/blob integrity for %s", path.Join(imgStore.RootDir(), repo))
	log.Info().Msg(execMsg)

	results, err := storage.CheckRepo(repo, imgStore)
	if err != nil {
		errMessage := fmt.Sprintf("error while running scrub for %s", path.Join(imgStore.RootDir(), repo))
		log.Error().Err(err).Msg(errMessage)
		log.Info().Msg(fmt.Sprintf("scrub unsuccessfully completed for %s", path.Join(imgStore.RootDir(), repo)))

		return err
	}

	for _, result := range results {
		if result.Status == "ok" {
			log.Info().
				Str("image", result.ImageName).
				Str("tag", result.Tag).
				Str("status", result.Status).
				Msg("scrub: blobs/manifest ok")
		} else {
			log.Warn().
				Str("image", result.ImageName).
				Str("tag", result.Tag).
				Str("status", result.Status).
				Str("error", result.Error).
				Msg("scrub: blobs/manifest affected")
		}
	}

	log.Info().Msg(fmt.Sprintf("scrub successfully completed for %s", path.Join(imgStore.RootDir(), repo)))

	return nil
}

type Task struct {
	imgStore storage.ImageStore
	repo     string
	log      log.Logger
}

func NewTask(imgStore storage.ImageStore, repo string, log log.Logger) *Task {
	return &Task{imgStore, repo, log}
}

func (scrubT *Task) DoWork() error {
	return RunScrubRepo(scrubT.imgStore, scrubT.repo, scrubT.log)
}
