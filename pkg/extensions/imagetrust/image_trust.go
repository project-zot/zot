//go:build imagetrust
// +build imagetrust

package imagetrust

import (
	"context"
	"encoding/json"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	aws1 "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	smanager "github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/log"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/scheduler"
)

const (
	defaultDirPerms  = 0o700
	defaultFilePerms = 0o644
)

type ImageTrustStore struct {
	CosignStorage   publicKeyStorage
	NotationStorage certificateStorage
}

type SecretsManagerClient interface {
	CreateSecret(ctx context.Context, params *secretsmanager.CreateSecretInput,
		optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	DeleteSecret(ctx context.Context, params *secretsmanager.DeleteSecretInput,
		optFns ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error)
	ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput,
		optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
}

type SecretsManagerCache interface {
	GetSecretString(secretID string) (string, error)
}

func NewLocalImageTrustStore(rootDir string) (*ImageTrustStore, error) {
	publicKeyStorage, err := NewPublicKeyLocalStorage(rootDir)
	if err != nil {
		return nil, err
	}

	certStorage, err := NewCertificateLocalStorage(rootDir)
	if err != nil {
		return nil, err
	}

	return &ImageTrustStore{
		CosignStorage:   publicKeyStorage,
		NotationStorage: certStorage,
	}, nil
}

func NewAWSImageTrustStore(region, endpoint string) (*ImageTrustStore, error) {
	secretsManagerClient, err := GetSecretsManagerClient(region, endpoint)
	if err != nil {
		return nil, err
	}

	secretsManagerCache := GetSecretsManagerRetrieval(region, endpoint)

	publicKeyStorage := NewPublicKeyAWSStorage(secretsManagerClient, secretsManagerCache)

	certStorage, err := NewCertificateAWSStorage(secretsManagerClient, secretsManagerCache)
	if err != nil {
		return nil, err
	}

	return &ImageTrustStore{
		CosignStorage:   publicKeyStorage,
		NotationStorage: certStorage,
	}, nil
}

func GetSecretsManagerClient(region, endpoint string) (*secretsmanager.Client, error) {
	customResolver := aws.EndpointResolverWithOptionsFunc(
		func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				PartitionID:   "aws",
				URL:           endpoint,
				SigningRegion: region,
			}, nil
		})

	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region),
		config.WithEndpointResolverWithOptions(customResolver))
	if err != nil {
		return nil, err
	}

	return secretsmanager.NewFromConfig(cfg), nil
}

func GetSecretsManagerRetrieval(region, endpoint string) *secretcache.Cache {
	endpointFunc := func(service, region string, optFns ...func(*endpoints.Options)) (endpoints.ResolvedEndpoint, error) {
		return endpoints.ResolvedEndpoint{
			PartitionID:   "aws",
			URL:           endpoint,
			SigningRegion: region,
		}, nil
	}
	customResolver := endpoints.ResolverFunc(endpointFunc)

	cfg := aws1.NewConfig().WithRegion(region).WithEndpointResolver(customResolver)

	newSession := session.Must(session.NewSession())

	client := smanager.New(newSession, cfg)
	// Create a custom CacheConfig struct
	config := secretcache.CacheConfig{
		MaxCacheSize: secretcache.DefaultMaxCacheSize,
		VersionStage: secretcache.DefaultVersionStage,
		CacheItemTTL: secretcache.DefaultCacheItemTTL,
	}

	// Instantiate the cache
	cache, _ := secretcache.New(
		func(c *secretcache.Cache) { c.CacheConfig = config },
		func(c *secretcache.Cache) { c.Client = client },
	)

	return cache
}

func (imgTrustStore *ImageTrustStore) VerifySignature(
	signatureType string, rawSignature []byte, sigKey string, manifestDigest godigest.Digest, manifestContent []byte,
	repo string,
) (string, time.Time, bool, error) {
	var manifest ispec.Manifest
	if err := json.Unmarshal(manifestContent, &manifest); err != nil {
		return "", time.Time{}, false, err
	}

	desc := ispec.Descriptor{
		MediaType: manifest.MediaType,
		Digest:    manifestDigest,
		Size:      int64(len(manifestContent)),
	}

	if manifestDigest.String() == "" {
		return "", time.Time{}, false, zerr.ErrBadManifestDigest
	}

	switch signatureType {
	case zcommon.CosignSignature:
		author, isValid, err := VerifyCosignSignature(imgTrustStore.CosignStorage, repo, manifestDigest, sigKey, rawSignature)

		return author, time.Time{}, isValid, err
	case zcommon.NotationSignature:
		return VerifyNotationSignature(imgTrustStore.NotationStorage, desc, manifestDigest.String(), rawSignature, sigKey)
	default:
		return "", time.Time{}, false, zerr.ErrInvalidSignatureType
	}
}

func NewTaskGenerator(metaDB mTypes.MetaDB, log log.Logger) scheduler.TaskGenerator {
	return &sigValidityTaskGenerator{
		repos:     []mTypes.RepoMetadata{},
		metaDB:    metaDB,
		repoIndex: -1,
		log:       log,
	}
}

type sigValidityTaskGenerator struct {
	repos     []mTypes.RepoMetadata
	metaDB    mTypes.MetaDB
	repoIndex int
	done      bool
	log       log.Logger
}

func (gen *sigValidityTaskGenerator) Next() (scheduler.Task, error) {
	if len(gen.repos) == 0 {
		ctx := context.Background()

		repos, err := gen.metaDB.GetMultipleRepoMeta(ctx, func(repoMeta mTypes.RepoMetadata) bool {
			return true
		})
		if err != nil {
			return nil, err
		}

		gen.repos = repos
	}

	gen.repoIndex++

	if gen.repoIndex >= len(gen.repos) {
		gen.done = true

		gen.log.Info().Msg("finished generating tasks for updating signatures validity")

		return nil, nil
	}

	return NewValidityTask(gen.metaDB, gen.repos[gen.repoIndex], gen.log), nil
}

func (gen *sigValidityTaskGenerator) IsDone() bool {
	return gen.done
}

func (gen *sigValidityTaskGenerator) IsReady() bool {
	return true
}

func (gen *sigValidityTaskGenerator) Reset() {
	gen.done = false
	gen.repoIndex = -1
	gen.repos = []mTypes.RepoMetadata{}

	gen.log.Info().Msg("finished resetting task generator for updating signatures validity")
}

type validityTask struct {
	metaDB mTypes.MetaDB
	repo   mTypes.RepoMetadata
	log    log.Logger
}

func NewValidityTask(metaDB mTypes.MetaDB, repo mTypes.RepoMetadata, log log.Logger) *validityTask {
	return &validityTask{metaDB, repo, log}
}

func (validityT *validityTask) DoWork(ctx context.Context) error {
	validityT.log.Info().Msg("updating signatures validity")

	for signedManifest, sigs := range validityT.repo.Signatures {
		if len(sigs[zcommon.CosignSignature]) != 0 || len(sigs[zcommon.NotationSignature]) != 0 {
			err := validityT.metaDB.UpdateSignaturesValidity(validityT.repo.Name, godigest.Digest(signedManifest))
			if err != nil {
				validityT.log.Info().Msg("error while verifying signatures")

				return err
			}
		}
	}

	validityT.log.Info().Msg("verifying signatures successfully completed")

	return nil
}
