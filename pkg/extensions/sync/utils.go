package sync

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strings"

	glob "github.com/bmatcuk/doublestar/v4"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/types"
	"github.com/notaryproject/notation-go-lib"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

type ReferenceList struct {
	References []notation.Descriptor `json:"references"`
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
		return nil, errors.ErrInvalidRepositoryName
	}

	return ref, nil
}

// filterRepos filters repos based on prefix given in the config.
func filterRepos(repos []string, contentList []Content, log log.Logger) map[int][]string {
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
	credsFile, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var creds CredentialsFile

	err = json.Unmarshal(credsFile, &creds)
	if err != nil {
		return nil, err
	}

	return creds, nil
}

func getHTTPClient(regCfg *RegistryConfig, credentials Credentials, log log.Logger) (*resty.Client, error) {
	client := resty.New()

	registryURL, err := url.Parse(regCfg.URL)
	if err != nil {
		log.Error().Err(err).Str("url", regCfg.URL).Msg("couldn't parse url")

		return nil, err
	}

	if regCfg.CertDir != "" {
		log.Debug().Msgf("sync: using certs directory: %s", regCfg.CertDir)
		clientCert := path.Join(regCfg.CertDir, "client.cert")
		clientKey := path.Join(regCfg.CertDir, "client.key")
		caCertPath := path.Join(regCfg.CertDir, "ca.crt")

		caCert, err := ioutil.ReadFile(caCertPath)
		if err != nil {
			log.Error().Err(err).Msg("couldn't read CA certificate")

			return nil, err
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})

		cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			log.Error().Err(err).Msg("couldn't read certificates key pairs")

			return nil, err
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

	return client, nil
}

func syncCosignSignature(client *resty.Client, storeController storage.StoreController,
	regURL url.URL, repo, digest string, log log.Logger) error {
	log.Info().Msg("syncing cosign signatures")

	getCosignManifestURL := regURL

	cosignEncodedDigest := strings.Replace(digest, ":", "-", 1) + ".sig"
	getCosignManifestURL.Path = path.Join(getCosignManifestURL.Path, "v2", repo, "manifests", cosignEncodedDigest)
	getCosignManifestURL.RawQuery = getCosignManifestURL.Query().Encode()

	mResp, err := client.R().Get(getCosignManifestURL.String())
	if err != nil {
		log.Error().Err(err).Str("url", getCosignManifestURL.String()).
			Msgf("couldn't get cosign manifest: %s", cosignEncodedDigest)

		return err
	}

	if mResp.IsError() {
		log.Info().Msgf("couldn't find any cosign signature from %s, status code: %d skipping",
			getCosignManifestURL.String(), mResp.StatusCode())

		return nil
	}

	var m ispec.Manifest

	err = json.Unmarshal(mResp.Body(), &m)
	if err != nil {
		log.Error().Err(err).Str("url", getCosignManifestURL.String()).
			Msgf("couldn't unmarshal cosign manifest %s", cosignEncodedDigest)

		return err
	}

	imageStore := storeController.GetImageStore(repo)

	for _, blob := range m.Layers {
		// get blob
		getBlobURL := regURL
		getBlobURL.Path = path.Join(getBlobURL.Path, "v2", repo, "blobs", blob.Digest.String())
		getBlobURL.RawQuery = getBlobURL.Query().Encode()

		resp, err := client.R().SetDoNotParseResponse(true).Get(getBlobURL.String())
		if err != nil {
			log.Error().Err(err).Msgf("couldn't get cosign blob: %s", blob.Digest.String())

			return err
		}

		if resp.IsError() {
			log.Info().Msgf("couldn't find cosign blob from %s, status code: %d", getBlobURL.String(), resp.StatusCode())

			return errors.ErrBadBlobDigest
		}

		defer resp.RawBody().Close()

		// push blob
		_, _, err = imageStore.FullBlobUpload(repo, resp.RawBody(), blob.Digest.String())
		if err != nil {
			log.Error().Err(err).Msg("couldn't upload cosign blob")

			return err
		}
	}

	// get config blob
	getBlobURL := regURL
	getBlobURL.Path = path.Join(getBlobURL.Path, "v2", repo, "blobs", m.Config.Digest.String())
	getBlobURL.RawQuery = getBlobURL.Query().Encode()

	resp, err := client.R().SetDoNotParseResponse(true).Get(getBlobURL.String())
	if err != nil {
		log.Error().Err(err).Msgf("couldn't get cosign config blob: %s", getBlobURL.String())

		return err
	}

	if resp.IsError() {
		log.Info().Msgf("couldn't find cosign config blob from %s, status code: %d", getBlobURL.String(), resp.StatusCode())

		return errors.ErrBadBlobDigest
	}

	defer resp.RawBody().Close()

	// push config blob
	_, _, err = imageStore.FullBlobUpload(repo, resp.RawBody(), m.Config.Digest.String())
	if err != nil {
		log.Error().Err(err).Msg("couldn't upload cosign blob")

		return err
	}

	// push manifest
	_, err = imageStore.PutImageManifest(repo, cosignEncodedDigest, ispec.MediaTypeImageManifest, mResp.Body())
	if err != nil {
		log.Error().Err(err).Msg("couldn't upload cosing manifest")

		return err
	}

	return nil
}

func syncNotarySignature(client *resty.Client, storeController storage.StoreController,
	regURL url.URL, repo, digest string, log log.Logger) error {
	log.Info().Msg("syncing notary signatures")

	getReferrersURL := regURL
	getRefManifestURL := regURL

	// based on manifest digest get referrers
	getReferrersURL.Path = path.Join(getReferrersURL.Path, "oras/artifacts/v1/", repo, "manifests", digest, "referrers")
	getReferrersURL.RawQuery = getReferrersURL.Query().Encode()

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetQueryParam("artifactType", "application/vnd.cncf.notary.v2.signature").
		Get(getReferrersURL.String())
	if err != nil {
		log.Error().Err(err).Msgf("couldn't get referrers from %s", getReferrersURL.String())

		return err
	}

	if resp.IsError() {
		log.Info().Msgf("couldn't find any notary signature from %s, status code: %d, skipping",
			getReferrersURL.String(), resp.StatusCode())

		return nil
	}

	var referrers ReferenceList

	err = json.Unmarshal(resp.Body(), &referrers)
	if err != nil {
		log.Error().Err(err).Msgf("couldn't unmarshal notary signature from %s", getReferrersURL.String())

		return err
	}

	imageStore := storeController.GetImageStore(repo)

	for _, ref := range referrers.References {
		// get referrer manifest
		getRefManifestURL.Path = path.Join(getRefManifestURL.Path, "v2", repo, "manifests", ref.Digest.String())
		getRefManifestURL.RawQuery = getRefManifestURL.Query().Encode()

		resp, err := client.R().
			Get(getRefManifestURL.String())
		if err != nil {
			log.Error().Err(err).Msgf("couldn't get notary manifest: %s", getRefManifestURL.String())

			return err
		}

		// read manifest
		var m artifactspec.Manifest

		err = json.Unmarshal(resp.Body(), &m)
		if err != nil {
			log.Error().Err(err).Msgf("couldn't unmarshal notary manifest: %s", getRefManifestURL.String())

			return err
		}

		for _, blob := range m.Blobs {
			getBlobURL := regURL
			getBlobURL.Path = path.Join(getBlobURL.Path, "v2", repo, "blobs", blob.Digest.String())
			getBlobURL.RawQuery = getBlobURL.Query().Encode()

			resp, err := client.R().SetDoNotParseResponse(true).Get(getBlobURL.String())
			if err != nil {
				log.Error().Err(err).Msgf("couldn't get notary blob: %s", getBlobURL.String())

				return err
			}

			defer resp.RawBody().Close()

			if resp.IsError() {
				log.Info().Msgf("couldn't find notary blob from %s, status code: %d",
					getBlobURL.String(), resp.StatusCode())

				return errors.ErrBadBlobDigest
			}

			_, _, err = imageStore.FullBlobUpload(repo, resp.RawBody(), blob.Digest.String())
			if err != nil {
				log.Error().Err(err).Msg("couldn't upload notary sig blob")

				return err
			}
		}

		_, err = imageStore.PutImageManifest(repo, ref.Digest.String(), artifactspec.MediaTypeArtifactManifest, resp.Body())
		if err != nil {
			log.Error().Err(err).Msg("couldn't upload notary sig manifest")

			return err
		}
	}

	return nil
}

func syncSignatures(client *resty.Client, storeController storage.StoreController,
	registryURL, repo, tag string, log log.Logger) error {
	log.Info().Msg("syncing signatures")
	// get manifest and find out its digest
	regURL, err := url.Parse(registryURL)
	if err != nil {
		log.Error().Err(err).Msgf("couldn't parse registry URL: %s", registryURL)

		return err
	}

	getManifestURL := *regURL

	getManifestURL.Path = path.Join(getManifestURL.Path, "v2", repo, "manifests", tag)

	resp, err := client.R().SetHeader("Content-Type", "application/json").Head(getManifestURL.String())
	if err != nil {
		log.Error().Err(err).Str("url", getManifestURL.String()).
			Msgf("couldn't query %s", registryURL)

		return err
	}

	digests, ok := resp.Header()["Docker-Content-Digest"]
	if !ok {
		log.Error().Err(errors.ErrBadBlobDigest).Str("url", getManifestURL.String()).
			Msgf("couldn't get digest for manifest: %s:%s", repo, tag)

		return errors.ErrBadBlobDigest
	}

	if len(digests) != 1 {
		log.Error().Err(errors.ErrBadBlobDigest).Str("url", getManifestURL.String()).
			Msgf("multiple digests found for: %s:%s", repo, tag)

		return errors.ErrBadBlobDigest
	}

	err = syncNotarySignature(client, storeController, *regURL, repo, digests[0], log)
	if err != nil {
		return err
	}

	err = syncCosignSignature(client, storeController, *regURL, repo, digests[0], log)
	if err != nil {
		return err
	}

	log.Info().Msg("successfully synced signatures")

	return nil
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

// sync feature will try to pull cosign signature because for sync cosign signature is just an image
// this function will check if tag is a cosign tag.
func isCosignTag(tag string) bool {
	if strings.HasPrefix(tag, "sha256-") && strings.HasSuffix(tag, ".sig") {
		return true
	}

	return false
}
