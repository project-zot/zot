package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	glob "github.com/bmatcuk/doublestar/v4"
	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/oci/layout"
	"github.com/containers/image/v5/types"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/sigstore/cosign/v2/pkg/oci/static"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/common"
	syncconf "zotregistry.io/zot/pkg/extensions/config/sync"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
)

type ReferenceList struct {
	References []artifactspec.Descriptor `json:"references"`
}

// getTagFromRef returns a tagged reference from an image reference.
func getTagFromRef(ref types.ImageReference, log log.Logger) reference.Tagged {
	tagged, isTagged := ref.DockerReference().(reference.Tagged)
	if !isTagged {
		log.Warn().Msgf("internal server error, reference %s does not have a tag, skipping", ref.DockerReference())
	}

	return tagged
}

// getImageTags lists all tags in a repository.
// It returns a string slice of tags and any error encountered.
func getImageTags(ctx context.Context, sysCtx *types.SystemContext, repoRef reference.Named) ([]string, error) {
	dockerRef, err := docker.NewReference(reference.TagNameOnly(repoRef))
	// hard to reach test case, injected error, see pkg/test/dev.go
	if err = test.Error(err); err != nil {
		return nil, err // Should never happen for a reference with tag and no digest
	}

	tags, err := docker.GetRepositoryTags(ctx, sysCtx, dockerRef)
	if err != nil {
		return nil, err
	}

	return tags, nil
}

// filterTagsByRegex filters images by tag regex given in the config.
func filterTagsByRegex(tags []string, regex string, log log.Logger) ([]string, error) {
	filteredTags := []string{}

	if len(tags) == 0 || regex == "" {
		return filteredTags, nil
	}

	log.Info().Msgf("start filtering using the regular expression: %s", regex)

	tagReg, err := regexp.Compile(regex)
	if err != nil {
		log.Error().Err(err).Str("regex", regex).Msg("couldn't compile regex")

		return filteredTags, err
	}

	for _, tag := range tags {
		if tagReg.MatchString(tag) {
			filteredTags = append(filteredTags, tag)
		}
	}

	return filteredTags, nil
}

// filterTagsBySemver filters tags by checking if they are semver compliant.
func filterTagsBySemver(tags []string, log log.Logger) []string {
	filteredTags := []string{}

	log.Info().Msg("start filtering using semver compliant rule")

	for _, tag := range tags {
		_, err := semver.NewVersion(tag)
		if err == nil {
			filteredTags = append(filteredTags, tag)
		}
	}

	return filteredTags
}

// parseRepositoryReference parses input into a reference.Named, and verifies that it names a repository, not an image.
func parseRepositoryReference(input string) (reference.Named, error) {
	ref, err := reference.ParseNormalizedNamed(input)
	if err != nil {
		return nil, err
	}

	if !reference.IsNameOnly(ref) {
		return nil, zerr.ErrInvalidRepositoryName
	}

	return ref, nil
}

// filterRepos filters repos based on prefix given in the config.
func filterRepos(repos []string, contentList []syncconf.Content, log log.Logger) map[int][]string {
	filtered := make(map[int][]string)

	for _, repo := range repos {
		for contentID, content := range contentList {
			var prefix string
			// handle prefixes starting with '/'
			if strings.HasPrefix(content.Prefix, "/") {
				prefix = content.Prefix[1:]
			} else {
				prefix = content.Prefix
			}

			matched, err := glob.Match(prefix, repo)
			if err != nil {
				log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Str("pattern",
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

// findRepoContentID return the contentID that maches the localRepo path for a given RegistryConfig in the config file.
func findRepoMatchingContentID(localRepo string, contentList []syncconf.Content) (int, error) {
	contentID := -1
	localRepo = strings.Trim(localRepo, "/")

	for cID, content := range contentList {
		// make sure prefix ends in "/" to extract the meta characters
		prefix := strings.Trim(content.Prefix, "/") + "/"
		destination := strings.Trim(content.Destination, "/")

		var patternSlice []string

		if content.StripPrefix {
			_, metaCharacters := glob.SplitPattern(prefix)
			patternSlice = append(patternSlice, destination, metaCharacters)
		} else {
			patternSlice = append(patternSlice, destination, prefix)
		}

		pattern := strings.Trim(strings.Join(patternSlice, "/"), "/")

		matched, err := glob.Match(pattern, localRepo)
		if err != nil {
			continue
		}

		if matched {
			contentID = cID

			break
		}
	}

	if contentID == -1 {
		return -1, zerr.ErrRegistryNoContent
	}

	return contentID, nil
}

func getRepoSource(localRepo string, content syncconf.Content) string {
	localRepo = strings.Trim(localRepo, "/")
	destination := strings.Trim(content.Destination, "/")
	prefix := strings.Trim(content.Prefix, "/*")

	var localRepoSlice []string

	localRepo = strings.TrimPrefix(localRepo, destination)
	localRepo = strings.Trim(localRepo, "/")

	if content.StripPrefix {
		localRepoSlice = append([]string{prefix}, localRepo)
	} else {
		localRepoSlice = []string{localRepo}
	}

	repoSource := strings.Join(localRepoSlice, "/")
	if repoSource == "/" {
		return repoSource
	}

	return strings.Trim(repoSource, "/")
}

// getRepoDestination returns the local storage path of the synced repo based on the specified destination.
func getRepoDestination(remoteRepo string, content syncconf.Content) string {
	remoteRepo = strings.Trim(remoteRepo, "/")
	destination := strings.Trim(content.Destination, "/")
	prefix := strings.Trim(content.Prefix, "/*")

	var repoDestSlice []string

	if content.StripPrefix {
		remoteRepo = strings.TrimPrefix(remoteRepo, prefix)
		remoteRepo = strings.Trim(remoteRepo, "/")
		repoDestSlice = append(repoDestSlice, destination, remoteRepo)
	} else {
		repoDestSlice = append(repoDestSlice, destination, remoteRepo)
	}

	repoDestination := strings.Join(repoDestSlice, "/")

	if repoDestination == "/" {
		return "/"
	}

	return strings.Trim(repoDestination, "/")
}

// Get sync.FileCredentials from file.
func getFileCredentials(filepath string) (syncconf.CredentialsFile, error) {
	credsFile, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var creds syncconf.CredentialsFile

	err = json.Unmarshal(credsFile, &creds)
	if err != nil {
		return nil, err
	}

	return creds, nil
}

func pushSyncedLocalImage(localRepo, reference, localCachePath string,
	repoDB repodb.RepoDB, imageStore storage.ImageStore, log log.Logger,
) error {
	log.Info().Msgf("pushing synced local image %s/%s:%s to local registry", localCachePath, localRepo, reference)

	var lockLatency time.Time

	metrics := monitoring.NewMetricsServer(false, log)

	cacheImageStore := local.NewImageStore(localCachePath, false,
		storage.DefaultGCDelay, false, false, log, metrics, nil, nil)

	manifestBlob, manifestDigest, mediaType, err := cacheImageStore.GetImageManifest(localRepo, reference)
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Str("dir", path.Join(cacheImageStore.RootDir(), localRepo)).
			Msgf("couldn't find %s manifest", reference)

		return err
	}

	// is image manifest
	switch mediaType {
	case ispec.MediaTypeImageManifest:
		if err := copyManifest(localRepo, manifestBlob, reference, repoDB, cacheImageStore, imageStore, log); err != nil {
			if errors.Is(err, zerr.ErrImageLintAnnotations) {
				log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Msg("couldn't upload manifest because of missing annotations")

				return nil
			}

			return err
		}
	case ispec.MediaTypeImageIndex:
		// is image index
		var indexManifest ispec.Index

		if err := json.Unmarshal(manifestBlob, &indexManifest); err != nil {
			log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Str("dir", path.Join(cacheImageStore.RootDir(), localRepo)).
				Msg("invalid JSON")

			return err
		}

		for _, manifest := range indexManifest.Manifests {
			cacheImageStore.RLock(&lockLatency)
			manifestBuf, err := cacheImageStore.GetBlobContent(localRepo, manifest.Digest)
			cacheImageStore.RUnlock(&lockLatency)

			if err != nil {
				log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Str("dir", path.Join(cacheImageStore.RootDir(), localRepo)).Str("digest", manifest.Digest.String()).
					Msg("couldn't find manifest which is part of an image index")

				return err
			}

			if err := copyManifest(localRepo, manifestBuf, manifest.Digest.String(), repoDB,
				cacheImageStore, imageStore, log); err != nil {
				if errors.Is(err, zerr.ErrImageLintAnnotations) {
					log.Error().Str("errorType", common.TypeOf(err)).
						Err(err).Msg("couldn't upload manifest because of missing annotations")

					return nil
				}

				return err
			}
		}

		_, err = imageStore.PutImageManifest(localRepo, reference, mediaType, manifestBlob)
		if err != nil {
			log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msg("couldn't upload manifest")

			return err
		}

		if repoDB != nil {
			err = repodb.SetMetadataFromInput(localRepo, reference, mediaType,
				manifestDigest, manifestBlob, imageStore, repoDB, log)
			if err != nil {
				return fmt.Errorf("failed to set metadata for image '%s %s': %w", localRepo, reference, err)
			}

			log.Debug().Msgf("successfully set metadata for %s:%s", localRepo, reference)
		}
	}

	return nil
}

func copyManifest(localRepo string, manifestContent []byte, reference string, repoDB repodb.RepoDB,
	cacheImageStore, imageStore storage.ImageStore, log log.Logger,
) error {
	var manifest ispec.Manifest

	var err error

	if err := json.Unmarshal(manifestContent, &manifest); err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Str("dir", path.Join(cacheImageStore.RootDir(), localRepo)).
			Msg("invalid JSON")

		return err
	}

	for _, blob := range manifest.Layers {
		err = copyBlob(localRepo, blob.Digest, blob.MediaType,
			cacheImageStore, imageStore, log)
		if err != nil {
			return err
		}
	}

	err = copyBlob(localRepo, manifest.Config.Digest, manifest.Config.MediaType,
		cacheImageStore, imageStore, log)
	if err != nil {
		return err
	}

	digest, err := imageStore.PutImageManifest(localRepo, reference,
		ispec.MediaTypeImageManifest, manifestContent)
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msg("couldn't upload manifest")

		return err
	}

	if repoDB != nil {
		err = repodb.SetMetadataFromInput(localRepo, reference, ispec.MediaTypeImageManifest,
			digest, manifestContent, imageStore, repoDB, log)
		if err != nil {
			log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msg("couldn't set metadata from input")

			return err
		}

		log.Debug().Msgf("successfully set metadata for %s:%s", localRepo, reference)
	}

	return nil
}

// Copy a blob from one image store to another image store.
func copyBlob(localRepo string, blobDigest godigest.Digest, blobMediaType string,
	souceImageStore, destinationImageStore storage.ImageStore, log log.Logger,
) error {
	if found, _, _ := destinationImageStore.CheckBlob(localRepo, blobDigest); found {
		// Blob is already at destination, nothing to do
		return nil
	}

	blobReadCloser, _, err := souceImageStore.GetBlob(localRepo, blobDigest, blobMediaType)
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).Err(err).
			Str("dir", path.Join(souceImageStore.RootDir(), localRepo)).
			Str("blob digest", blobDigest.String()).Str("media type", blobMediaType).
			Msg("couldn't read blob")

		return err
	}
	defer blobReadCloser.Close()

	_, _, err = destinationImageStore.FullBlobUpload(localRepo, blobReadCloser, blobDigest)
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).Err(err).
			Str("blob digest", blobDigest.String()).Str("media type", blobMediaType).
			Msg("couldn't upload blob")
	}

	return err
}

// sync needs transport to be stripped to not be wrongly interpreted as an image reference
// at a non-fully qualified registry (hostname as image and port as tag).
func StripRegistryTransport(url string) string {
	return strings.Replace(strings.Replace(url, "http://", "", 1), "https://", "", 1)
}

// get an ImageReference given the registry, repo and tag.
func getImageRef(registryDomain, repo, ref string) (types.ImageReference, error) {
	repoRef, err := parseRepositoryReference(fmt.Sprintf("%s/%s", registryDomain, repo))
	if err != nil {
		return nil, err
	}

	var namedRepoRef reference.Named

	digest, ok := parseReference(ref)
	if ok {
		namedRepoRef, err = reference.WithDigest(repoRef, digest)
		if err != nil {
			return nil, err
		}
	} else {
		namedRepoRef, err = reference.WithTag(repoRef, ref)
		if err != nil {
			return nil, err
		}
	}

	imageRef, err := docker.NewReference(namedRepoRef)
	if err != nil {
		return nil, err
	}

	return imageRef, err
}

// get a local ImageReference used to temporary store one synced image.
func getLocalImageRef(localCachePath, repo, reference string) (types.ImageReference, error) {
	if _, err := os.ReadDir(localCachePath); err != nil {
		return nil, err
	}

	localRepo := path.Join(localCachePath, repo)

	_, refIsDigest := parseReference(reference)

	if !refIsDigest {
		localRepo = fmt.Sprintf("%s:%s", localRepo, reference)
	}

	localImageRef, err := layout.ParseReference(localRepo)
	if err != nil {
		return nil, err
	}

	return localImageRef, nil
}

// Returns the localCachePath with an UUID at the end. Only to be called once per repo.
func getLocalCachePath(imageStore storage.ImageStore, repo string) (string, error) {
	localRepoPath := path.Join(imageStore.RootDir(), repo, SyncBlobUploadDir)
	// check if SyncBlobUploadDir exists, create if not
	var err error
	if _, err = os.ReadDir(localRepoPath); os.IsNotExist(err) {
		if err = os.MkdirAll(localRepoPath, local.DefaultDirPerms); err != nil {
			return "", err
		}
	}

	if err != nil {
		return "", err
	}

	// create uuid folder
	uuid, err := guuid.NewV4()
	// hard to reach test case, injected error, see pkg/test/dev.go
	if err := test.Error(err); err != nil {
		return "", err
	}

	localCachePath := path.Join(localRepoPath, uuid.String())

	cachedRepoPath := path.Join(localCachePath, repo)
	if err = os.MkdirAll(cachedRepoPath, local.DefaultDirPerms); err != nil {
		return "", err
	}

	return localCachePath, nil
}

// canSkipImage returns whether or not we already synced this image.
func canSkipImage(repo, tag string, digest godigest.Digest, imageStore storage.ImageStore, log log.Logger,
) (bool, error) {
	// check image already synced
	_, localImageManifestDigest, _, err := imageStore.GetImageManifest(repo, tag)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoNotFound) || errors.Is(err, zerr.ErrManifestNotFound) {
			return false, nil
		}

		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msgf("couldn't get local image %s:%s manifest", repo, tag)

		return false, err
	}

	if localImageManifestDigest != digest {
		log.Info().Msgf("upstream image %s:%s digest changed, syncing again", repo, tag)

		return false, nil
	}

	return true, nil
}

// parse a reference, return its digest and if it's valid.
func parseReference(reference string) (godigest.Digest, bool) {
	var ok bool

	d, err := godigest.Parse(reference)
	if err == nil {
		ok = true
	}

	return d, ok
}

func manifestsEqual(manifest1, manifest2 ispec.Manifest) bool {
	if manifest1.Config.Digest == manifest2.Config.Digest &&
		manifest1.Config.MediaType == manifest2.Config.MediaType &&
		manifest1.Config.Size == manifest2.Config.Size {
		if descriptorsEqual(manifest1.Layers, manifest2.Layers) {
			return true
		}
	}

	return false
}

func artifactsEqual(manifest1, manifest2 ispec.Artifact) bool {
	if manifest1.ArtifactType == manifest2.ArtifactType &&
		manifest1.MediaType == manifest2.MediaType {
		if descriptorsEqual(manifest1.Blobs, manifest2.Blobs) {
			return true
		}
	}

	return false
}

func artifactDescriptorsEqual(desc1, desc2 []artifactspec.Descriptor) bool {
	if len(desc1) != len(desc2) {
		return false
	}

	for id, desc := range desc1 {
		if desc.Digest != desc2[id].Digest ||
			desc.Size != desc2[id].Size ||
			desc.MediaType != desc2[id].MediaType ||
			desc.ArtifactType != desc2[id].ArtifactType {
			return false
		}
	}

	return true
}

func descriptorsEqual(desc1, desc2 []ispec.Descriptor) bool {
	if len(desc1) != len(desc2) {
		return false
	}

	for id, desc := range desc1 {
		if !descriptorEqual(desc, desc2[id]) {
			return false
		}
	}

	return true
}

func descriptorEqual(desc1, desc2 ispec.Descriptor) bool {
	if desc1.Size == desc2.Size &&
		desc1.Digest == desc2.Digest &&
		desc1.MediaType == desc2.MediaType &&
		desc1.Annotations[static.SignatureAnnotationKey] == desc2.Annotations[static.SignatureAnnotationKey] {
		return true
	}

	return false
}

func isSupportedMediaType(mediaType string) bool {
	return mediaType == ispec.MediaTypeImageIndex ||
		mediaType == ispec.MediaTypeImageManifest ||
		mediaType == manifest.DockerV2ListMediaType ||
		mediaType == manifest.DockerV2Schema2MediaType
}

func getImageRefManifest(ctx context.Context, upstreamCtx *types.SystemContext, imageRef types.ImageReference,
	log log.Logger,
) ([]byte, string, error) {
	imageSource, err := imageRef.NewImageSource(ctx, upstreamCtx)
	if err != nil {
		log.Error().Err(err).Msgf("couldn't get upstream image %s manifest details", imageRef.DockerReference())

		return []byte{}, "", err
	}

	defer imageSource.Close()

	manifestBuf, mediaType, err := imageSource.GetManifest(ctx, nil)
	if err != nil {
		log.Error().Err(err).Msgf("couldn't get upstream image %s manifest mediaType", imageRef.DockerReference())

		return []byte{}, "", err
	}

	return manifestBuf, mediaType, nil
}

func syncImageWithRefs(ctx context.Context, localRepo, upstreamRepo, reference string,
	upstreamImageRef types.ImageReference, utils syncContextUtils, sig *signaturesCopier,
	localCachePath string, log log.Logger,
) (bool, error) {
	var skipped bool

	imageStore := sig.storeController.GetImageStore(localRepo)

	manifestBuf, mediaType, err := getImageRefManifest(ctx, utils.upstreamCtx, upstreamImageRef, log)
	if err != nil {
		return skipped, err
	}

	upstreamImageDigest := godigest.FromBytes(manifestBuf)

	if !isSupportedMediaType(mediaType) {
		if mediaType == ispec.MediaTypeArtifactManifest {
			err = sig.syncOCIArtifact(localRepo, upstreamRepo, reference, manifestBuf) //nolint
			if err != nil {
				log.Error().Err(err).Msgf("couldn't sync oci artifact with artifact mediaType: %s",
					upstreamImageRef.DockerReference())

				return skipped, err
			}
		}

		return skipped, nil
	}

	// get upstream signatures
	cosignManifest, err := sig.getCosignManifest(upstreamRepo, upstreamImageDigest.String())
	if err != nil {
		log.Error().Err(err).Msgf("couldn't get upstream image %s cosign manifest", upstreamImageRef.DockerReference())
	}

	index, err := sig.getOCIRefs(upstreamRepo, upstreamImageDigest.String())
	if err != nil {
		log.Error().Err(err).Msgf("couldn't get upstream image %s OCI references", upstreamImageRef.DockerReference())
	}

	// check if upstream image is signed
	if cosignManifest == nil && len(getNotationManifestsFromOCIRefs(index)) == 0 {
		// upstream image not signed
		if utils.enforceSignatures {
			// skip unsigned images
			log.Info().Msgf("skipping image without signature %s", upstreamImageRef.DockerReference())
			skipped = true

			return skipped, nil
		}
	}

	skipImage, err := canSkipImage(localRepo, upstreamImageDigest.String(), upstreamImageDigest, imageStore, log)
	if err != nil {
		log.Error().Err(err).Msgf("couldn't check if the upstream image %s can be skipped",
			upstreamImageRef.DockerReference())
	}

	if !skipImage {
		// sync image
		localImageRef, err := getLocalImageRef(localCachePath, localRepo, reference)
		if err != nil {
			log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msgf("couldn't obtain a valid image reference for reference %s/%s:%s",
				localCachePath, localRepo, reference)

			return skipped, err
		}

		log.Info().Msgf("copying image %s to %s", upstreamImageRef.DockerReference(), localCachePath)

		if err = retry.RetryIfNecessary(ctx, func() error {
			_, err = copy.Image(ctx, utils.policyCtx, localImageRef, upstreamImageRef, &utils.copyOptions)

			return err
		}, utils.retryOptions); err != nil {
			log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msgf("error while copying image %s to %s",
				upstreamImageRef.DockerReference(), localCachePath)

			return skipped, err
		}

		// push from cache to repo
		err = pushSyncedLocalImage(localRepo, reference, localCachePath, sig.repoDB, imageStore, log)
		if err != nil {
			log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msgf("error while pushing synced cached image %s",
				fmt.Sprintf("%s/%s:%s", localCachePath, localRepo, reference))

			return skipped, err
		}
	} else {
		log.Info().Msgf("already synced image %s, checking its signatures", upstreamImageRef.DockerReference())
	}

	// sync signatures
	if err = retry.RetryIfNecessary(ctx, func() error {
		err = sig.syncOCIRefs(localRepo, upstreamRepo, upstreamImageDigest.String(), index)
		if err != nil {
			return err
		}

		refs, err := sig.getORASRefs(upstreamRepo, upstreamImageDigest.String())
		if err != nil && !errors.Is(err, zerr.ErrSyncReferrerNotFound) {
			return err
		}

		err = sig.syncORASRefs(localRepo, upstreamRepo, upstreamImageDigest.String(), refs)
		if err != nil {
			return err
		}

		err = sig.syncCosignSignature(localRepo, upstreamRepo, upstreamImageDigest.String(), cosignManifest)
		if err != nil {
			return err
		}

		return nil
	}, utils.retryOptions); err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msgf("couldn't copy referrer for %s", upstreamImageRef.DockerReference())

		return skipped, err
	}

	log.Info().Msgf("successfully synced image %s", upstreamImageRef.DockerReference())

	return skipped, nil
}
