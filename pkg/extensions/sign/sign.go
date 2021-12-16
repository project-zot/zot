package sign

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	zoterrors "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

type RepoInfo struct {
	IsValidated  bool
	VisitedCount int
}

type Config struct {
	VerificationInterval string
	PublicKeys           map[string]string
}

func Run(config *Config, log log.Logger, is storage.ImageStore) {

	timeInterval, _ := time.ParseDuration(config.VerificationInterval)
	ticker := time.NewTicker(timeInterval)

	reposInfoMap := make(map[string]*RepoInfo)

	go func() {
		for ; true; <-ticker.C {
			repos, err := is.GetRepositories()
			fmt.Println(repos)

			if err != nil {
				log.Error().Err(err).Msg("error while getting repositories")
			}

			for _, repo := range repos {
				_, ok := reposInfoMap[repo]

				if !ok {
					reposInfoMap[repo] = &RepoInfo{
						IsValidated:  false,
						VisitedCount: 0,
					}
				}

				if !reposInfoMap[repo].IsValidated && reposInfoMap[repo].VisitedCount < 2 {
					if err != nil {
						log.Error().Err(err).Msg("error while getting repository stats")
					}
					err = VerifyRepo(repo, is, config.PublicKeys[repo])
					if errors.Is(err, zoterrors.ErrNoSignatureProvided) {
						log.Error().Err(err).Msg("no signature provided for image " + repo)
					} else if err != nil {
						log.Error().Err(err).Msg("failed verification, repo: " + repo)
					} else {
						reposInfoMap[repo].IsValidated = true
					}
					reposInfoMap[repo].VisitedCount++
				}

				if reposInfoMap[repo].VisitedCount == 2 {
					buf, err := is.GetIndexContent(repo)
					if err != nil {
						log.Error().Err(err).Msg("failed to read index.json")
					}
					var index ispec.Index
					if err := json.Unmarshal(buf, &index); err != nil {
						log.Error().Err(err).Msg("invalid JSON")
					}
					digest := index.Manifests[0].Digest.String()
					err = is.DeleteImageManifest(repo, digest)
					if err != nil {
						log.Error().Err(err).Msg("cant delete manifest:(")
					}
					delete(reposInfoMap, repo)
					fmt.Println(len(index.Manifests))
					if len(index.Manifests) == 1 {
						fmt.Println("AM INTRAT!!")
						os.RemoveAll(path.Join(is.RootDir(), repo))
					}
				}
			}
		}
	}()
}
