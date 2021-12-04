package sync

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"strings"

	glob "github.com/bmatcuk/doublestar/v4"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/types"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

// getTagFromRef returns a tagged reference from an image reference.
func getTagFromRef(ref types.ImageReference, log log.Logger) reference.Tagged {
	tagged, isTagged := ref.DockerReference().(reference.Tagged)
	if !isTagged {
		log.Warn().Msgf("internal server error, reference %s does not have a tag, skipping", ref.DockerReference())
		return nil
	}

	return tagged
}

// parseRepositoryReference parses input into a reference.Named, and verifies that it names a repository, not an image.
func parseRepositoryReference(input string) (reference.Named, error) {
	ref, err := reference.ParseNormalizedNamed(input)
	if err != nil {
		return nil, err
	}

	if !reference.IsNameOnly(ref) {
		return nil, errors.ErrInvalidRepositoryName
	}

	return ref, nil
}

// filterRepos filters repos based on prefix given in the config.
func filterRepos(repos []string, content []Content, log log.Logger) map[int][]string {
	filtered := make(map[int][]string)

	for _, repo := range repos {
		for contentID, c := range content {
			var prefix string
			// handle prefixes starting with '/'
			if strings.HasPrefix(c.Prefix, "/") {
				prefix = c.Prefix[1:]
			} else {
				prefix = c.Prefix
			}

			matched, err := glob.Match(prefix, repo)
			if err != nil {
				log.Error().Err(err).Str("pattern",
					prefix).Msg("error while parsing glob pattern, skipping it...")
				continue
			}

			if matched {
				filtered[contentID] = append(filtered[contentID], repo)
				break
			}
		}
	}

	return filtered
}

// Get sync.FileCredentials from file.
func getFileCredentials(filepath string) (CredentialsFile, error) {
	f, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var creds CredentialsFile

	err = json.Unmarshal(f, &creds)
	if err != nil {
		return nil, err
	}

	return creds, nil
}

func pushSyncedLocalImage(repo, tag, uuid string,
	storeController storage.StoreController, log log.Logger) error {
	log.Info().Msgf("pushing synced local image %s:%s to local registry", repo, tag)

	imageStore := storeController.GetImageStore(repo)

	metrics := monitoring.NewMetricsServer(false, log)
	cacheImageStore := storage.NewImageStore(path.Join(imageStore.RootDir(), repo, SyncBlobUploadDir, uuid),
		false, false, log, metrics)

	manifestContent, _, _, err := cacheImageStore.GetImageManifest(repo, tag)
	if err != nil {
		log.Error().Err(err).Str("dir", path.Join(cacheImageStore.RootDir(), repo)).Msg("couldn't find index.json")
		return err
	}

	var manifest ispec.Manifest

	if err := json.Unmarshal(manifestContent, &manifest); err != nil {
		log.Error().Err(err).Str("dir", path.Join(cacheImageStore.RootDir(), repo)).Msg("invalid JSON")
		return err
	}

	for _, blob := range manifest.Layers {
		blobReader, _, err := cacheImageStore.GetBlob(repo, blob.Digest.String(), blob.MediaType)
		if err != nil {
			log.Error().Err(err).Str("dir", path.Join(cacheImageStore.RootDir(),
				repo)).Str("blob digest", blob.Digest.String()).Msg("couldn't read blob")
			return err
		}

		_, _, err = imageStore.FullBlobUpload(repo, blobReader, blob.Digest.String())
		if err != nil {
			log.Error().Err(err).Str("blob digest", blob.Digest.String()).Msg("couldn't upload blob")
			return err
		}
	}

	blobReader, _, err := cacheImageStore.GetBlob(repo, manifest.Config.Digest.String(), manifest.Config.MediaType)
	if err != nil {
		log.Error().Err(err).Str("dir", path.Join(cacheImageStore.RootDir(),
			repo)).Str("blob digest", manifest.Config.Digest.String()).Msg("couldn't read config blob")
		return err
	}

	_, _, err = imageStore.FullBlobUpload(repo, blobReader, manifest.Config.Digest.String())
	if err != nil {
		log.Error().Err(err).Str("blob digest", manifest.Config.Digest.String()).Msg("couldn't upload config blob")
		return err
	}

	_, err = imageStore.PutImageManifest(repo, tag, ispec.MediaTypeImageManifest, manifestContent)
	if err != nil {
		log.Error().Err(err).Msg("couldn't upload manifest")
		return err
	}

	log.Info().Msgf("removing temporary cached synced repo %s", path.Join(cacheImageStore.RootDir(), repo))

	if err := os.RemoveAll(path.Join(cacheImageStore.RootDir(), repo)); err != nil {
		log.Error().Err(err).Msg("couldn't remove locally cached sync repo")
		return err
	}

	return nil
}
