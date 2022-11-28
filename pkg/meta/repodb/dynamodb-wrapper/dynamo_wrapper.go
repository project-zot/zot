package dynamo

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb" //nolint:go-staticcheck
	"zotregistry.io/zot/pkg/meta/repodb/common"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
)

type DBWrapper struct {
	Client                *dynamodb.Client
	RepoMetaTablename     string
	ManifestMetaTablename string
	Log                   log.Logger
}

type DBDriverParameters struct {
	Endpoint, Region, RepoMetaTablename, ManifestMetaTablename string
}

func NewDynamoDBWrapper(params DBDriverParameters) (*DBWrapper, error) {
	// custom endpoint resolver to point to localhost
	customResolver := aws.EndpointResolverWithOptionsFunc(
		func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				PartitionID:   "aws",
				URL:           params.Endpoint,
				SigningRegion: region,
			}, nil
		})

	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(params.Region),
		config.WithEndpointResolverWithOptions(customResolver))
	if err != nil {
		return nil, err
	}

	// Using the Config value, create the DynamoDB client
	return &DBWrapper{
		Client:                dynamodb.NewFromConfig(cfg),
		RepoMetaTablename:     params.RepoMetaTablename,
		ManifestMetaTablename: params.ManifestMetaTablename,
		Log:                   log.Logger{Logger: zerolog.New(os.Stdout)},
	}, nil
}

func (dwr DBWrapper) SetRepoDescription(repo, description string) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	repoMeta.Description = description

	err = dwr.setRepoMeta(repo, repoMeta)

	return err
}

func (dwr DBWrapper) IncrementRepoStars(repo string) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	repoMeta.Stars++

	err = dwr.setRepoMeta(repo, repoMeta)

	return err
}

func (dwr DBWrapper) DecrementRepoStars(repo string) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	if repoMeta.Stars > 0 {
		repoMeta.Stars--
	}

	err = dwr.setRepoMeta(repo, repoMeta)

	return err
}

func (dwr DBWrapper) GetRepoStars(repo string) (int, error) {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return 0, err
	}

	return repoMeta.Stars, nil
}

func (dwr DBWrapper) SetRepoLogo(repo string, logoPath string) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	repoMeta.LogoPath = logoPath

	err = dwr.setRepoMeta(repo, repoMeta)

	return err
}

func (dwr DBWrapper) SetRepoTag(repo string, tag string, manifestDigest godigest.Digest) error {
	if err := common.ValidateRepoTagInput(repo, tag, manifestDigest); err != nil {
		return err
	}

	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.RepoMetaTablename),
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return err
	}

	repoMeta := repodb.RepoMetadata{
		Name: repo,
		Tags: map[string]string{},
	}

	if resp.Item != nil {
		err := attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
		if err != nil {
			return err
		}
	}

	repoMeta.Tags[tag] = manifestDigest.String()

	err = dwr.setRepoMeta(repo, repoMeta)

	return err
}

func (dwr DBWrapper) DeleteRepoTag(repo string, tag string) error {
	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.RepoMetaTablename),
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return err
	}

	if resp.Item == nil {
		return nil
	}

	var repoMeta repodb.RepoMetadata

	err = attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
	if err != nil {
		return err
	}

	delete(repoMeta.Tags, tag)

	if len(repoMeta.Tags) == 0 {
		_, err := dwr.Client.DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
			TableName: aws.String(dwr.RepoMetaTablename),
			Key: map[string]types.AttributeValue{
				"RepoName": &types.AttributeValueMemberS{Value: repo},
			},
		})

		return err
	}

	repoAttributeValue, err := attributevalue.Marshal(repoMeta)
	if err != nil {
		return err
	}

	_, err = dwr.Client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#RM": "RepoMetadata",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":RepoMetadata": repoAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{
				Value: repo,
			},
		},
		TableName:        aws.String(dwr.RepoMetaTablename),
		UpdateExpression: aws.String("SET #RM = :RepoMetadata"),
	})

	return err
}

func (dwr DBWrapper) GetRepoMeta(repo string) (repodb.RepoMetadata, error) {
	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.RepoMetaTablename),
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return repodb.RepoMetadata{}, err
	}

	if resp.Item == nil {
		return repodb.RepoMetadata{}, zerr.ErrRepoMetaNotFound
	}

	var repoMeta repodb.RepoMetadata

	err = attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
	if err != nil {
		return repodb.RepoMetadata{}, err
	}

	return repoMeta, nil
}

func (dwr DBWrapper) GetManifestMeta(manifestDigest godigest.Digest,
) (repodb.ManifestMetadata, error) { //nolint:contextcheck
	resp, err := dwr.Client.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.ManifestMetaTablename),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: manifestDigest.String()},
		},
	})
	if err != nil {
		return repodb.ManifestMetadata{}, err
	}

	if resp.Item == nil {
		return repodb.ManifestMetadata{}, zerr.ErrManifestMetaNotFound
	}

	var manifestMetadata repodb.ManifestMetadata

	err = attributevalue.Unmarshal(resp.Item["ManifestMetadata"], &manifestMetadata)
	if err != nil {
		return repodb.ManifestMetadata{}, err
	}

	return manifestMetadata, nil
}

func (dwr DBWrapper) SetManifestMeta(manifestDigest godigest.Digest, manifestMeta repodb.ManifestMetadata) error {
	if manifestMeta.Signatures == nil {
		manifestMeta.Signatures = map[string][]string{}
	}

	mmAttributeValue, err := attributevalue.Marshal(manifestMeta)
	if err != nil {
		return err
	}

	_, err = dwr.Client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#MM": "ManifestMetadata",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":ManifestMetadata": mmAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{
				Value: manifestDigest.String(),
			},
		},
		TableName:        aws.String(dwr.ManifestMetaTablename),
		UpdateExpression: aws.String("SET #MM = :ManifestMetadata"),
	})

	return err
}

func (dwr DBWrapper) IncrementManifestDownloads(manifestDigest godigest.Digest) error {
	manifestMeta, err := dwr.GetManifestMeta(manifestDigest)
	if err != nil {
		return err
	}

	manifestMeta.DownloadCount++

	err = dwr.SetManifestMeta(manifestDigest, manifestMeta)

	return err
}

func (dwr DBWrapper) AddManifestSignature(manifestDigest godigest.Digest, sigMeta repodb.SignatureMetadata) error {
	manifestMeta, err := dwr.GetManifestMeta(manifestDigest)
	if err != nil {
		return err
	}

	manifestMeta.Signatures[sigMeta.SignatureType] = append(manifestMeta.Signatures[sigMeta.SignatureType],
		sigMeta.SignatureDigest.String())

	err = dwr.SetManifestMeta(manifestDigest, manifestMeta)

	return err
}

func (dwr DBWrapper) DeleteSignature(manifestDigest godigest.Digest, sigMeta repodb.SignatureMetadata) error {
	manifestMeta, err := dwr.GetManifestMeta(manifestDigest)
	if err != nil {
		return err
	}

	sigType := sigMeta.SignatureType

	for i, sig := range manifestMeta.Signatures[sigType] {
		if sig == sigMeta.SignatureDigest.String() {
			signaturesCount := len(manifestMeta.Signatures[sigType])

			if signaturesCount < 1 {
				manifestMeta.Signatures[sigType] = []string{}

				return nil
			}

			// put element to be deleted at the end of the array
			manifestMeta.Signatures[sigType][i] = manifestMeta.Signatures[sigType][signaturesCount-1]

			// trim the last element
			manifestMeta.Signatures[sigType] = manifestMeta.Signatures[sigType][:signaturesCount-1]

			err := dwr.SetManifestMeta(manifestDigest, manifestMeta)

			return err
		}
	}

	return nil
}

func (dwr DBWrapper) GetMultipleRepoMeta(ctx context.Context,
	filter func(repoMeta repodb.RepoMetadata) bool, requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, error) {
	var (
		repoMetaAttributeIterator AttributesIterator
		pageFinder                repodb.PageFinder
	)

	repoMetaAttributeIterator = NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	pageFinder, err := repodb.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return nil, err
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			// log
			return []repodb.RepoMetadata{}, err
		}

		var repoMeta repodb.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []repodb.RepoMetadata{}, err
		}

		if ok, err := localCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		if filter(repoMeta) {
			pageFinder.Add(repodb.DetailedRepoMeta{
				RepoMeta: repoMeta,
			})
		}
	}

	foundRepos := pageFinder.Page()

	return foundRepos, err
}

func (dwr DBWrapper) SearchRepos(ctx context.Context, searchText string, filter repodb.Filter,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	var (
		foundManifestMetadataMap = make(map[string]repodb.ManifestMetadata)
		manifestMetadataMap      = make(map[string]repodb.ManifestMetadata)

		repoMetaAttributeIterator AttributesIterator
		pageFinder                repodb.PageFinder
	)

	repoMetaAttributeIterator = NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	pageFinder, err := repodb.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, err
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			// log
			return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, err
		}

		var repoMeta repodb.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, err
		}

		if ok, err := localCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		if score := common.ScoreRepoName(searchText, repoMeta.Name); score != -1 {
			var (
				// specific values used for sorting that need to be calculated based on all manifests from the repo
				repoDownloads     = 0
				repoLastUpdated   time.Time
				firstImageChecked = true
				osSet             = map[string]bool{}
				archSet           = map[string]bool{}
				isSigned          = false
			)

			for _, manifestDigest := range repoMeta.Tags {
				var manifestMeta repodb.ManifestMetadata

				manifestMeta, manifestDownloaded := manifestMetadataMap[manifestDigest]

				if !manifestDownloaded {
					manifestMeta, err = dwr.GetManifestMeta(godigest.Digest(manifestDigest)) //nolint:contextcheck
					if err != nil {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{},
							errors.Wrapf(err, "repodb: error while getting manifest metadata for digest %s", manifestDigest)
					}
				}

				// get fields related to filtering
				var configContent ispec.Image

				err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
				if err != nil {
					return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{},
						errors.Wrapf(err, "repodb: error while unmarshaling config content for digest %s", manifestDigest)
				}

				osSet[configContent.OS] = true
				archSet[configContent.Architecture] = true

				// get fields related to sorting
				repoDownloads += manifestMeta.DownloadCount

				imageLastUpdated, err := common.GetImageLastUpdatedTimestamp(manifestMeta.ConfigBlob)
				if err != nil {
					return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{},
						errors.Wrapf(err, "repodb: error while unmarshaling image config referenced by digest %s", manifestDigest)
				}

				if firstImageChecked || repoLastUpdated.Before(imageLastUpdated) {
					repoLastUpdated = imageLastUpdated
					firstImageChecked = false

					isSigned = common.CheckIsSigned(manifestMeta.Signatures)
				}

				manifestMetadataMap[manifestDigest] = manifestMeta
			}

			repoFilterData := repodb.FilterData{
				OsList:   common.GetMapKeys(osSet),
				ArchList: common.GetMapKeys(archSet),
				IsSigned: isSigned,
			}

			if !common.AcceptedByFilter(filter, repoFilterData) {
				continue
			}

			pageFinder.Add(repodb.DetailedRepoMeta{
				RepoMeta:   repoMeta,
				Score:      score,
				Downloads:  repoDownloads,
				UpdateTime: repoLastUpdated,
			})
		}
	}

	foundRepos := pageFinder.Page()

	// keep just the manifestMeta we need
	for _, repoMeta := range foundRepos {
		for _, manifestDigest := range repoMeta.Tags {
			foundManifestMetadataMap[manifestDigest] = manifestMetadataMap[manifestDigest]
		}
	}

	return foundRepos, foundManifestMetadataMap, err
}

func (dwr DBWrapper) SearchTags(ctx context.Context, searchText string, filter repodb.Filter,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	var (
		foundManifestMetadataMap  = make(map[string]repodb.ManifestMetadata)
		manifestMetadataMap       = make(map[string]repodb.ManifestMetadata)
		repoMetaAttributeIterator = NewBaseDynamoAttributesIterator(
			dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
		)

		pageFinder repodb.PageFinder
	)

	pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, err
	}

	searchedRepo, searchedTag, err := common.GetRepoTag(searchText)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{},
			errors.Wrap(err, "repodb: error while parsing search text, invalid format")
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			// log
			return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, err
		}

		var repoMeta repodb.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, err
		}

		if ok, err := localCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		if repoMeta.Name == searchedRepo {
			matchedTags := make(map[string]string)
			// take all manifestMetas
			for tag, manifestDigest := range repoMeta.Tags {
				if !strings.HasPrefix(tag, searchedTag) {
					continue
				}

				matchedTags[tag] = manifestDigest

				// in case tags reference the same manifest we don't download from DB multiple times
				if manifestMeta, manifestExists := manifestMetadataMap[manifestDigest]; manifestExists {
					manifestMetadataMap[manifestDigest] = manifestMeta

					continue
				}

				manifestMeta, err := dwr.GetManifestMeta(godigest.Digest(manifestDigest)) //nolint:contextcheck
				if err != nil {
					return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{},
						errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", manifestDigest)
				}

				var configContent ispec.Image

				err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
				if err != nil {
					return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{},
						errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", manifestDigest)
				}

				imageFilterData := repodb.FilterData{
					OsList:   []string{configContent.OS},
					ArchList: []string{configContent.Architecture},
					IsSigned: false,
				}

				if !common.AcceptedByFilter(filter, imageFilterData) {
					delete(matchedTags, tag)
					delete(manifestMetadataMap, manifestDigest)

					continue
				}

				manifestMetadataMap[manifestDigest] = manifestMeta
			}

			repoMeta.Tags = matchedTags

			pageFinder.Add(repodb.DetailedRepoMeta{
				RepoMeta: repoMeta,
			})
		}
	}

	foundRepos := pageFinder.Page()

	// keep just the manifestMeta we need
	for _, repoMeta := range foundRepos {
		for _, manifestDigest := range repoMeta.Tags {
			foundManifestMetadataMap[manifestDigest] = manifestMetadataMap[manifestDigest]
		}
	}

	return foundRepos, foundManifestMetadataMap, err
}

func (dwr DBWrapper) setRepoMeta(repo string, repoMeta repodb.RepoMetadata) error {
	repoAttributeValue, err := attributevalue.Marshal(repoMeta)
	if err != nil {
		return err
	}

	_, err = dwr.Client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#RM": "RepoMetadata",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":RepoMetadata": repoAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{
				Value: repo,
			},
		},
		TableName:        aws.String(dwr.RepoMetaTablename),
		UpdateExpression: aws.String("SET #RM = :RepoMetadata"),
	})

	return err
}

func (dwr DBWrapper) createRepoMetaTable() error {
	_, err := dwr.Client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String(dwr.RepoMetaTablename),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("RepoName"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("RepoName"),
				KeyType:       types.KeyTypeHash,
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})

	return err
}

func (dwr DBWrapper) deleteRepoMetaTable() error {
	_, err := dwr.Client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
		TableName: aws.String(dwr.RepoMetaTablename),
	})

	return err
}

func (dwr DBWrapper) ResetRepoMetaTable() error {
	err := dwr.deleteRepoMetaTable()
	if err != nil {
		return err
	}

	return dwr.createRepoMetaTable()
}

func (dwr DBWrapper) createManifestMetaTable() error {
	_, err := dwr.Client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String(dwr.ManifestMetaTablename),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("Digest"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("Digest"),
				KeyType:       types.KeyTypeHash,
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})

	return err
}

func (dwr DBWrapper) deleteManifestMetaTable() error {
	_, err := dwr.Client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
		TableName: aws.String(dwr.ManifestMetaTablename),
	})

	return err
}

func (dwr DBWrapper) ResetManifestMetaTable() error {
	err := dwr.deleteManifestMetaTable()
	if err != nil {
		return err
	}

	return dwr.createManifestMetaTable()
}

func (dwr DBWrapper) SearchDigests(ctx context.Context, searchText string, requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	panic("not implemented")
}

func (dwr DBWrapper) SearchLayers(ctx context.Context, searchText string, requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	panic("not implemented")
}

func (dwr DBWrapper) SearchForAscendantImages(ctx context.Context, searchText string, requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	panic("not implemented")
}

func (dwr DBWrapper) SearchForDescendantImages(ctx context.Context, searchText string, requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	panic("not implemented")
}
