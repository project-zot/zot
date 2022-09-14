package sync

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"

	glob "github.com/bmatcuk/doublestar/v4"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/oci/layout"
	"github.com/containers/image/v5/types"
	guuid "github.com/gofrs/uuid"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/sigstore/cosign/pkg/oci/static"
	"gopkg.in/resty.v1"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	storConstants "zotregistry.io/zot/pkg/storage/constants"
	"zotregistry.io/zot/pkg/test"
)

type ReferenceList struct {
	References []artifactspec.Descriptor `json:"references"`
}

func TypeOf(v interface{}) string {
	return fmt.Sprintf("%T", v)
}

// getTagFromRef returns a tagged reference from an image reference.
func getTagFromRef(ref types.ImageReference, log log.Logger) reference.Tagged {
	tagged, isTagged := ref.DockerReference().(reference.Tagged)
	if !isTagged {
		log.Warn().Msgf("internal server error, reference %s does not have a tag, skipping", ref.DockerReference())
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
		return nil, zerr.ErrInvalidRepositoryName
	}

	return ref, nil
}

// filterRepos filters repos based on prefix given in the config.
func filterRepos(repos []string, contentList []config.Content, log log.Logger) map[int][]string {
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
				log.Error().Str("errorType", TypeOf(err)).
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
func findRepoMatchingContentID(localRepo string, contentList []config.Content) (int, error) {
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

func getRepoSource(localRepo string, content config.Content) string {
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
func getRepoDestination(remoteRepo string, content config.Content) string {
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
func getFileCredentials(filepath string) (config.CredentialsFile, error) {
	credsFile, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var creds config.CredentialsFile

	err = json.Unmarshal(credsFile, &creds)
	if err != nil {
		return nil, err
	}

	return creds, nil
}

func getHTTPClient(regCfg *config.RegistryConfig, upstreamURL string, credentials config.Credentials,
	log log.Logger,
) (*resty.Client, *url.URL, error) {
	client := resty.New()

	if !common.Contains(regCfg.URLs, upstreamURL) {
		return nil, nil, zerr.ErrSyncInvalidUpstreamURL
	}

	registryURL, err := url.Parse(upstreamURL)
	if err != nil {
		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Str("url", upstreamURL).Msg("couldn't parse url")

		return nil, nil, err
	}

	if regCfg.CertDir != "" {
		log.Debug().Msgf("sync: using certs directory: %s", regCfg.CertDir)
		clientCert := path.Join(regCfg.CertDir, "client.cert")
		clientKey := path.Join(regCfg.CertDir, "client.key")
		caCertPath := path.Join(regCfg.CertDir, "ca.crt")

		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msg("couldn't read CA certificate")

			return nil, nil, err
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})

		cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msg("couldn't read certificates key pairs")

			return nil, nil, err
		}

		client.SetCertificates(cert)
	}

	// nolint: gosec
	if regCfg.TLSVerify != nil && !*regCfg.TLSVerify && registryURL.Scheme == "https" {
		client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	}

	if credentials.Username != "" && credentials.Password != "" {
		log.Debug().Msgf("sync: using basic auth")
		client.SetBasicAuth(credentials.Username, credentials.Password)
	}

	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(httpMaxRedirectsCount))

	return client, registryURL, nil
}

func pushSyncedLocalImage(localRepo, tag, localCachePath string,
	imageStore storage.ImageStore, log log.Logger,
) error {
	log.Info().Msgf("pushing synced local image %s/%s:%s to local registry", localCachePath, localRepo, tag)

	metrics := monitoring.NewMetricsServer(false, log)

	cacheImageStore := local.NewImageStore(localCachePath, false,
		storConstants.DefaultGCDelay, false, false, log, metrics, nil)

	manifestContent, _, _, err := cacheImageStore.GetImageManifest(localRepo, tag)
	if err != nil {
		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Str("dir", path.Join(cacheImageStore.RootDir(), localRepo)).
			Msg("couldn't find index.json")

		return err
	}

	var manifest ispec.Manifest

	if err := json.Unmarshal(manifestContent, &manifest); err != nil {
		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Str("dir", path.Join(cacheImageStore.RootDir(), localRepo)).
			Msg("invalid JSON")

		return err
	}

	for _, blob := range manifest.Layers {
		err = copyBlob(localRepo, blob.Digest.String(), blob.MediaType,
			cacheImageStore, imageStore, log)
		if err != nil {
			return err
		}
	}

	err = copyBlob(localRepo, manifest.Config.Digest.String(), manifest.Config.MediaType,
		cacheImageStore, imageStore, log)
	if err != nil {
		return err
	}

	_, err = imageStore.PutImageManifest(localRepo, tag,
		ispec.MediaTypeImageManifest, manifestContent)
	if err != nil {
		if errors.Is(err, zerr.ErrImageLintAnnotations) {
			log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msg("couldn't upload manifest because of missing annotations")

			return nil
		}

		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msg("couldn't upload manifest")

		return err
	}

	return nil
}

// Copy a blob from one image store to another image store.
func copyBlob(localRepo, blobDigest, blobMediaType string,
	souceImageStore, destinationImageStore storage.ImageStore, log log.Logger,
) error {
	if found, _, _ := destinationImageStore.CheckBlob(localRepo, blobDigest); found {
		// Blob is already at destination, nothing to do
		return nil
	}

	blobReadCloser, _, err := souceImageStore.GetBlob(localRepo, blobDigest, blobMediaType)
	if err != nil {
		log.Error().Str("errorType", TypeOf(err)).Err(err).
			Str("dir", path.Join(souceImageStore.RootDir(), localRepo)).
			Str("blob digest", blobDigest).Str("media type", blobMediaType).
			Msg("couldn't read blob")

		return err
	}
	defer blobReadCloser.Close()

	_, _, err = destinationImageStore.FullBlobUpload(localRepo, blobReadCloser, blobDigest)
	if err != nil {
		log.Error().Str("errorType", TypeOf(err)).Err(err).
			Str("blob digest", blobDigest).Str("media type", blobMediaType).
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
func getImageRef(registryDomain, repo, tag string) (types.ImageReference, error) {
	repoRef, err := parseRepositoryReference(fmt.Sprintf("%s/%s", registryDomain, repo))
	if err != nil {
		return nil, err
	}

	taggedRepoRef, err := reference.WithTag(repoRef, tag)
	if err != nil {
		return nil, err
	}

	imageRef, err := docker.NewReference(taggedRepoRef)
	if err != nil {
		return nil, err
	}

	return imageRef, err
}

// get a local ImageReference used to temporary store one synced image.
func getLocalImageRef(localCachePath, repo, tag string) (types.ImageReference, error) {
	if _, err := os.ReadDir(localCachePath); err != nil {
		return nil, err
	}

	localRepo := path.Join(localCachePath, repo)
	localTaggedRepo := fmt.Sprintf("%s:%s", localRepo, tag)

	localImageRef, err := layout.ParseReference(localTaggedRepo)
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
func canSkipImage(repo, tag, digest string, imageStore storage.ImageStore, log log.Logger) (bool, error) {
	// check image already synced
	_, localImageManifestDigest, _, err := imageStore.GetImageManifest(repo, tag)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoNotFound) || errors.Is(err, zerr.ErrManifestNotFound) {
			return false, nil
		}

		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msgf("couldn't get local image %s:%s manifest", repo, tag)

		return false, err
	}

	if localImageManifestDigest != digest {
		log.Info().Msgf("upstream image %s:%s digest changed, syncing again", repo, tag)

		return false, nil
	}

	return true, nil
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
		if desc.Digest != desc2[id].Digest ||
			desc.Size != desc2[id].Size ||
			desc.MediaType != desc2[id].MediaType ||
			desc.Annotations[static.SignatureAnnotationKey] != desc2[id].Annotations[static.SignatureAnnotationKey] {
			return false
		}
	}

	return true
}
