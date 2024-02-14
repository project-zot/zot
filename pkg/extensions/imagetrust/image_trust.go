//go:build imagetrust
// +build imagetrust

package imagetrust

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	aws1 "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	smanager "github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	smithy "github.com/aws/smithy-go"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/errors"
	zcommon "zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/scheduler"
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

func IsResourceExistsException(err error) bool {
	if opErr, ok := err.(*smithy.OperationError); ok { //nolint: errorlint
		if resErr, ok := opErr.Err.(*http.ResponseError); ok { //nolint: errorlint
			if _, ok := resErr.Err.(*types.ResourceExistsException); ok { //nolint: errorlint
				return true
			}
		}

		return false
	}

	return false
}

func (imgTrustStore *ImageTrustStore) VerifySignature(
	signatureType string, rawSignature []byte, sigKey string, manifestDigest godigest.Digest, imageMeta mTypes.ImageMeta,
	repo string,
) (mTypes.Author, mTypes.ExpiryDate, mTypes.Validity, error) {
	desc := ispec.Descriptor{
		MediaType: imageMeta.MediaType,
		Digest:    imageMeta.Digest,
		Size:      imageMeta.Size,
	}

	if manifestDigest.String() == "" {
		return "", time.Time{}, false, zerr.ErrBadSignatureManifestDigest
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
		repos:     []mTypes.RepoMeta{},
		metaDB:    metaDB,
		repoIndex: -1,
		log:       log,
	}
}

type sigValidityTaskGenerator struct {
	repos     []mTypes.RepoMeta
	metaDB    mTypes.MetaDB
	repoIndex int
	done      bool
	log       log.Logger
}

func (gen *sigValidityTaskGenerator) Name() string {
	return "SignatureValidationGenerator"
}

func (gen *sigValidityTaskGenerator) Next() (scheduler.Task, error) {
	if len(gen.repos) == 0 {
		ctx := context.Background()

		repos, err := gen.metaDB.GetMultipleRepoMeta(ctx, func(repoMeta mTypes.RepoMeta) bool {
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
	gen.repos = []mTypes.RepoMeta{}

	gen.log.Info().Msg("finished resetting task generator for updating signatures validity")
}

type validityTask struct {
	metaDB mTypes.MetaDB
	repo   mTypes.RepoMeta
	log    log.Logger
}

func NewValidityTask(metaDB mTypes.MetaDB, repo mTypes.RepoMeta, log log.Logger) *validityTask {
	return &validityTask{metaDB, repo, log}
}

func (validityT *validityTask) DoWork(ctx context.Context) error {
	validityT.log.Info().Msg("update signatures validity")

	for signedManifest, sigs := range validityT.repo.Signatures {
		if zcommon.IsContextDone(ctx) {
			return ctx.Err()
		}

		if len(sigs[zcommon.CosignSignature]) != 0 || len(sigs[zcommon.NotationSignature]) != 0 {
			err := validityT.metaDB.UpdateSignaturesValidity(ctx, validityT.repo.Name, godigest.Digest(signedManifest))
			if err != nil {
				validityT.log.Info().Msg("failed to verify signatures")

				return err
			}
		}
	}

	validityT.log.Info().Msg("update signatures validity completed")

	return nil
}

func (validityT *validityTask) String() string {
	return fmt.Sprintf("{sigValidityTaskGenerator: %s, repo: %s}",
		"signatures validity task", // description of generator's task purpose
		validityT.repo.Name)
}

func (validityT *validityTask) Name() string {
	return "SignatureValidityTask"
}
