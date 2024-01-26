//go:build scrub
// +build scrub

package scrub

import (
	"context"
	"fmt"
	"path"

	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/storage"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
)

// Scrub Extension for repo...
func RunScrubRepo(ctx context.Context, imgStore storageTypes.ImageStore, repo string, log log.Logger) error {
	execMsg := fmt.Sprintf("executing scrub to check manifest/blob integrity for %s", path.Join(imgStore.RootDir(), repo))
	log.Info().Msg(execMsg)

	results, err := storage.CheckRepo(ctx, repo, imgStore)
	if err != nil {
		errMessage := fmt.Sprintf("failed to run scrub for %s", path.Join(imgStore.RootDir(), repo))
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
				Str("component", "scrub").
				Msg("blobs/manifest ok")
		} else {
			log.Warn().
				Str("image", result.ImageName).
				Str("tag", result.Tag).
				Str("status", result.Status).
				Str("affected blob", result.AffectedBlob).
				Str("error", result.Error).
				Str("component", "scrub").
				Msg("blobs/manifest affected")
		}
	}

	log.Info().Msg(fmt.Sprintf("scrub successfully completed for %s", path.Join(imgStore.RootDir(), repo)))

	return nil
}

type Task struct {
	imgStore storageTypes.ImageStore
	repo     string
	log      log.Logger
}

func NewTask(imgStore storageTypes.ImageStore, repo string, log log.Logger) *Task {
	return &Task{imgStore, repo, log}
}

func (scrubT *Task) DoWork(ctx context.Context) error {
	return RunScrubRepo(ctx, scrubT.imgStore, scrubT.repo, scrubT.log) //nolint: contextcheck
}

func (scrubT *Task) String() string {
	return fmt.Sprintf("{taskGenerator: \"%s\", repo: \"%s\"}",
		"image scrub", // description of generator's task purpose
		scrubT.repo)
}

func (scrubT *Task) Name() string {
	return "ScrubTask"
}
