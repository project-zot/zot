package sync

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/log"
	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/types"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/resty.v1"
)

const (
	maxRetries = 3
	delay      = 5 * time.Minute
)

// /v2/_catalog struct.
type catalog struct {
	Repositories []string `json:"repositories"`
}

// key is registry address.
type CredentialsFile map[string]Credentials

type Credentials struct {
	Username string
	Password string
}

type Config struct {
	CredentialsFile string
	Registries      []RegistryConfig
}

type RegistryConfig struct {
	URL          string
	PollInterval time.Duration
	Content      []Content
	TLSVerify    *bool
	OnDemand     bool
	CertDir      string
}

type Content struct {
	Prefix string
	Tags   *Tags
}

type Tags struct {
	Regex  *string
	Semver *bool
}

// getUpstreamCatalog gets all repos from a registry.
func getUpstreamCatalog(regCfg *RegistryConfig, credentials Credentials, log log.Logger) (catalog, error) {
	var c catalog

	registryCatalogURL := fmt.Sprintf("%s%s", regCfg.URL, "/v2/_catalog")
	client := resty.New()

	if regCfg.CertDir != "" {
		log.Debug().Msgf("sync: using certs directory: %s", regCfg.CertDir)
		clientCert := fmt.Sprintf("%s/client.cert", regCfg.CertDir)
		clientKey := fmt.Sprintf("%s/client.key", regCfg.CertDir)
		caCertPath := fmt.Sprintf("%s/ca.crt", regCfg.CertDir)

		caCert, err := ioutil.ReadFile(caCertPath)
		if err != nil {
			return c, err
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})

		cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return c, err
		}

		client.SetCertificates(cert)
	}

	if credentials.Username != "" && credentials.Password != "" {
		log.Debug().Msgf("sync: using basic auth")
		client.SetBasicAuth(credentials.Username, credentials.Password)
	}

	resp, err := client.R().SetHeader("Content-Type", "application/json").Get(registryCatalogURL)
	if err != nil {
		log.Err(err).Msgf("couldn't query %s", registryCatalogURL)
		return c, err
	}

	if resp.IsError() {
		log.Error().Msgf("couldn't query %s, status code: %d, body: %s", registryCatalogURL,
			resp.StatusCode(), resp.Body())
		return c, errors.ErrSyncMissingCatalog
	}

	err = json.Unmarshal(resp.Body(), &c)
	if err != nil {
		log.Err(err).Str("body", string(resp.Body())).Msg("couldn't unmarshal registry's catalog")
		return c, err
	}

	return c, nil
}

// getImageTags lists all tags in a repository.
// It returns a string slice of tags and any error encountered.
func getImageTags(ctx context.Context, sysCtx *types.SystemContext, repoRef reference.Named) ([]string, error) {
	dockerRef, err := docker.NewReference(reference.TagNameOnly(repoRef))
	if err != nil {
		return nil, err // Should never happen for a reference with tag and no digest
	}

	tags, err := docker.GetRepositoryTags(ctx, sysCtx, dockerRef)
	if err != nil {
		return nil, err
	}

	return tags, nil
}

// filterImagesByTagRegex filters images by tag regex give in the config.
func filterImagesByTagRegex(upstreamReferences *[]types.ImageReference, content Content, log log.Logger) error {
	refs := *upstreamReferences

	if content.Tags == nil {
		// no need to filter anything
		return nil
	}

	if content.Tags.Regex != nil {
		log.Info().Msgf("start filtering using the regular expression: %s", *content.Tags.Regex)

		tagReg, err := regexp.Compile(*content.Tags.Regex)
		if err != nil {
			return err
		}

		n := 0

		for _, ref := range refs {
			tagged := getTagFromRef(ref, log)
			if tagged != nil {
				if tagReg.MatchString(tagged.Tag()) {
					refs[n] = ref
					n++
				}
			}
		}

		refs = refs[:n]
	}

	*upstreamReferences = refs

	return nil
}

// filterImagesBySemver filters images by checking if their tags are semver compliant.
func filterImagesBySemver(upstreamReferences *[]types.ImageReference, content Content, log log.Logger) {
	refs := *upstreamReferences

	if content.Tags == nil {
		return
	}

	if content.Tags.Semver != nil && *content.Tags.Semver {
		log.Info().Msg("start filtering using semver compliant rule")

		n := 0

		for _, ref := range refs {
			tagged := getTagFromRef(ref, log)
			if tagged != nil {
				_, ok := semver.NewVersion(tagged.Tag())
				if ok == nil {
					refs[n] = ref
					n++
				}
			}
		}

		refs = refs[:n]
	}

	*upstreamReferences = refs
}

// imagesToCopyFromRepos lists all images given a registry name and its repos.
func imagesToCopyFromUpstream(registryName string, repos []string, sourceCtx *types.SystemContext,
	content Content, log log.Logger) ([]types.ImageReference, error) {
	var upstreamReferences []types.ImageReference

	for _, repoName := range repos {
		repoRef, err := parseRepositoryReference(fmt.Sprintf("%s/%s", registryName, repoName))
		if err != nil {
			return nil, err
		}

		tags, err := getImageTags(context.Background(), sourceCtx, repoRef)
		if err != nil {
			return nil, err
		}

		for _, tag := range tags {
			taggedRef, err := reference.WithTag(repoRef, tag)
			if err != nil {
				log.Err(err).Msgf("error creating a reference for repository %s and tag %q", repoRef.Name(), tag)
				return nil, err
			}

			ref, err := docker.NewReference(taggedRef)
			if err != nil {
				log.Err(err).Msgf("cannot obtain a valid image reference for transport %q and reference %s",
					docker.Transport.Name(), taggedRef.String())
				return nil, err
			}

			upstreamReferences = append(upstreamReferences, ref)
		}
	}

	log.Debug().Msgf("upstream refs to be copied: %v", upstreamReferences)

	err := filterImagesByTagRegex(&upstreamReferences, content, log)
	if err != nil {
		return []types.ImageReference{}, err
	}

	log.Debug().Msgf("remaining upstream refs to be copied: %v", upstreamReferences)
	filterImagesBySemver(&upstreamReferences, content, log)

	log.Debug().Msgf("remaining upstream refs to be copied: %v", upstreamReferences)

	return upstreamReferences, nil
}

func getCopyOptions(upstreamCtx, localCtx *types.SystemContext) copy.Options {
	options := copy.Options{
		DestinationCtx: localCtx,
		SourceCtx:      upstreamCtx,
		// force only oci manifest MIME type
		ForceManifestMIMEType: ispec.MediaTypeImageManifest,
	}

	return options
}

func getUpstreamContext(regCfg *RegistryConfig, credentials Credentials) *types.SystemContext {
	upstreamCtx := &types.SystemContext{}

	upstreamCtx.DockerCertPath = regCfg.CertDir
	upstreamCtx.DockerDaemonCertPath = regCfg.CertDir

	if regCfg.TLSVerify != nil && *regCfg.TLSVerify {
		upstreamCtx.DockerDaemonInsecureSkipTLSVerify = false
		upstreamCtx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(false)
	} else {
		upstreamCtx.DockerDaemonInsecureSkipTLSVerify = true
		upstreamCtx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(true)
	}

	if credentials != (Credentials{}) {
		upstreamCtx.DockerAuthConfig = &types.DockerAuthConfig{
			Username: credentials.Username,
			Password: credentials.Password,
		}
	}

	return upstreamCtx
}

func syncRegistry(regCfg RegistryConfig, log log.Logger, localRegistryName string, localCtx *types.SystemContext,
	policyCtx *signature.PolicyContext, credentials Credentials) error {
	if len(regCfg.Content) == 0 {
		log.Info().Msgf("no content found for %s, will not run periodically sync", regCfg.URL)
		return nil
	}

	log.Info().Msgf("syncing registry: %s", regCfg.URL)

	var err error

	log.Debug().Msg("getting upstream context")

	upstreamCtx := getUpstreamContext(&regCfg, credentials)
	options := getCopyOptions(upstreamCtx, localCtx)

	retryOptions := &retry.RetryOptions{
		MaxRetry: maxRetries,
		Delay:    delay,
	}

	var catalog catalog

	if err = retry.RetryIfNecessary(context.Background(), func() error {
		catalog, err = getUpstreamCatalog(&regCfg, credentials, log)
		return err
	}, retryOptions); err != nil {
		log.Error().Err(err).Msg("error while getting upstream catalog, retrying...")
		return err
	}

	upstreamRegistryName := strings.Replace(strings.Replace(regCfg.URL, "http://", "", 1), "https://", "", 1)

	log.Info().Msg("filtering repos based on sync prefixes")

	repos := filterRepos(catalog.Repositories, regCfg.Content)

	log.Info().Msgf("got repos: %v", repos)

	var images []types.ImageReference

	for contentID, repos := range repos {
		r := repos
		id := contentID

		if err = retry.RetryIfNecessary(context.Background(), func() error {
			refs, err := imagesToCopyFromUpstream(upstreamRegistryName, r, upstreamCtx, regCfg.Content[id], log)
			images = append(images, refs...)
			return err
		}, retryOptions); err != nil {
			log.Error().Err(err).Msg("error while getting images references from upstream, retrying...")
			return err
		}
	}

	if len(images) == 0 {
		log.Info().Msg("no images to copy, no need to sync")
		return nil
	}

	for _, ref := range images {
		upstreamRef := ref

		suffix := strings.Replace(ref.DockerReference().String(), upstreamRegistryName, "", 1)

		localRef, err := docker.Transport.ParseReference(
			fmt.Sprintf("//%s%s", localRegistryName, suffix),
		)
		if err != nil {
			return err
		}

		log.Info().Msgf("copying image %s to %s", upstreamRef.DockerReference().Name(), localRef.DockerReference().Name())

		if err = retry.RetryIfNecessary(context.Background(), func() error {
			_, err = copy.Image(context.Background(), policyCtx, localRef, upstreamRef, &options)
			return err
		}, retryOptions); err != nil {
			log.Error().Err(err).Msgf("error while copying image %s to %s",
				upstreamRef.DockerReference().Name(), localRef.DockerReference().Name())
			return err
		}
	}

	log.Info().Msgf("finished syncing %s", regCfg.URL)

	return nil
}

func getLocalContexts(serverCert, serverKey,
	caCert string, log log.Logger) (*types.SystemContext, *signature.PolicyContext, error) {
	log.Debug().Msg("getting local context")

	var policy *signature.Policy

	var err error

	localCtx := &types.SystemContext{}

	if serverCert != "" && serverKey != "" {
		certsDir, err := copyLocalCerts(serverCert, serverKey, caCert, log)
		if err != nil {
			return &types.SystemContext{}, &signature.PolicyContext{}, err
		}

		localCtx.DockerDaemonCertPath = certsDir
		localCtx.DockerCertPath = certsDir

		policy, err = signature.DefaultPolicy(localCtx)
		if err != nil {
			return &types.SystemContext{}, &signature.PolicyContext{}, err
		}
	} else {
		localCtx.DockerDaemonInsecureSkipTLSVerify = true
		localCtx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(true)
		policy = &signature.Policy{Default: []signature.PolicyRequirement{signature.NewPRInsecureAcceptAnything()}}
	}

	policyContext, err := signature.NewPolicyContext(policy)
	if err != nil {
		return &types.SystemContext{}, &signature.PolicyContext{}, err
	}

	return localCtx, policyContext, nil
}

func Run(cfg Config, log log.Logger, address, port, serverCert, serverKey, caCert string) error {
	localCtx, policyCtx, err := getLocalContexts(serverCert, serverKey, caCert, log)
	if err != nil {
		return err
	}

	localRegistry := strings.Replace(fmt.Sprintf("%s:%s", address, port), "0.0.0.0", "127.0.0.1", 1)

	var credentialsFile CredentialsFile

	if cfg.CredentialsFile != "" {
		credentialsFile, err = getFileCredentials(cfg.CredentialsFile)
		if err != nil {
			log.Error().Err(err).Msgf("couldn't get registry credentials from %s", cfg.CredentialsFile)
			return err
		}
	}

	var ticker *time.Ticker

	for _, regCfg := range cfg.Registries {
		// schedule each registry sync
		ticker = time.NewTicker(regCfg.PollInterval)

		upstreamRegistry := strings.Replace(strings.Replace(regCfg.URL, "http://", "", 1), "https://", "", 1)

		go func(regCfg RegistryConfig) {
			defer os.RemoveAll(certsDir)
			// run sync first, then run on interval
			if err := syncRegistry(regCfg, log, localRegistry, localCtx, policyCtx,
				credentialsFile[upstreamRegistry]); err != nil {
				log.Err(err).Msg("sync exited with error, stopping it...")
				ticker.Stop()
			}

			// run on intervals
			for range ticker.C {
				if err := syncRegistry(regCfg, log, localRegistry, localCtx, policyCtx,
					credentialsFile[upstreamRegistry]); err != nil {
					log.Err(err).Msg("sync exited with error, stopping it...")
					ticker.Stop()
				}
			}
		}(regCfg)
	}

	log.Info().Msg("finished setting up sync")

	return nil
}
