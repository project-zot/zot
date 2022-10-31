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
	"zotregistry.io/zot/pkg/meta/repodb/dynamodb-wrapper/iterator"
	dynamoParams "zotregistry.io/zot/pkg/meta/repodb/dynamodb-wrapper/params"
	"zotregistry.io/zot/pkg/meta/repodb/version"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
)

type DBWrapper struct {
	Client                *dynamodb.Client
	RepoMetaTablename     string
	ManifestDataTablename string
	VersionTablename      string
	Patches               []func(client *dynamodb.Client, tableNames map[string]string) error
	Log                   log.Logger
}

func NewDynamoDBWrapper(params dynamoParams.DBDriverParameters) (*DBWrapper, error) {
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

	dynamoWrapper := DBWrapper{
		Client:                dynamodb.NewFromConfig(cfg),
		RepoMetaTablename:     params.RepoMetaTablename,
		ManifestDataTablename: params.ManifestDataTablename,
		VersionTablename:      params.VersionTablename,
		Patches:               version.GetDynamoDBPatches(),
		Log:                   log.Logger{Logger: zerolog.New(os.Stdout)},
	}

	err = dynamoWrapper.createVersionTable()
	if err != nil {
		return nil, err
	}

	err = dynamoWrapper.createRepoMetaTable()
	if err != nil {
		return nil, err
	}

	err = dynamoWrapper.createManifestDataTable()
	if err != nil {
		return nil, err
	}

	// Using the Config value, create the DynamoDB client
	return &dynamoWrapper, nil
}

func (dwr DBWrapper) SetManifestData(manifestDigest godigest.Digest, manifestData repodb.ManifestData) error {
	mdAttributeValue, err := attributevalue.Marshal(manifestData)
	if err != nil {
		return err
	}

	_, err = dwr.Client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#MD": "ManifestData",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":ManifestData": mdAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{
				Value: manifestDigest.String(),
			},
		},
		TableName:        aws.String(dwr.ManifestDataTablename),
		UpdateExpression: aws.String("SET #MD = :ManifestData"),
	})

	return err
}

func (dwr DBWrapper) GetManifestData(manifestDigest godigest.Digest) (repodb.ManifestData, error) {
	resp, err := dwr.Client.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.ManifestDataTablename),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: manifestDigest.String()},
		},
	})
	if err != nil {
		return repodb.ManifestData{}, err
	}

	if resp.Item == nil {
		return repodb.ManifestData{}, zerr.ErrManifestDataNotFound
	}

	var manifestData repodb.ManifestData

	err = attributevalue.Unmarshal(resp.Item["ManifestData"], &manifestData)
	if err != nil {
		return repodb.ManifestData{}, err
	}

	return manifestData, nil
}

func (dwr DBWrapper) SetManifestMeta(repo string, manifestDigest godigest.Digest, manifestMeta repodb.ManifestMetadata,
) error {
	if manifestMeta.Signatures == nil {
		manifestMeta.Signatures = repodb.ManifestSignatures{}
	}

	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		if !errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return err
		}

		repoMeta = repodb.RepoMetadata{
			Name:       repo,
			Tags:       map[string]repodb.Descriptor{},
			Statistics: map[string]repodb.DescriptorStatistics{},
			Signatures: map[string]repodb.ManifestSignatures{},
		}
	}

	err = dwr.SetManifestData(manifestDigest, repodb.ManifestData{
		ManifestBlob: manifestMeta.ManifestBlob,
		ConfigBlob:   manifestMeta.ConfigBlob,
	})
	if err != nil {
		return err
	}

	updatedRepoMeta := common.UpdateManifestMeta(repoMeta, manifestDigest, manifestMeta)

	err = dwr.setRepoMeta(repo, updatedRepoMeta)
	if err != nil {
		return err
	}

	return err
}

func (dwr DBWrapper) GetManifestMeta(repo string, manifestDigest godigest.Digest,
) (repodb.ManifestMetadata, error) { //nolint:contextcheck
	manifestData, err := dwr.GetManifestData(manifestDigest)
	if err != nil {
		if errors.Is(err, zerr.ErrManifestDataNotFound) {
			return repodb.ManifestMetadata{}, zerr.ErrManifestMetaNotFound
		}

		return repodb.ManifestMetadata{},
			errors.Wrapf(err, "error while constructing manifest meta for manifest '%s' from repo '%s'",
				manifestDigest, repo)
	}

	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return repodb.ManifestMetadata{}, zerr.ErrManifestMetaNotFound
		}

		return repodb.ManifestMetadata{},
			errors.Wrapf(err, "error while constructing manifest meta for manifest '%s' from repo '%s'",
				manifestDigest, repo)
	}

	manifestMetadata := repodb.ManifestMetadata{}

	manifestMetadata.ManifestBlob = manifestData.ManifestBlob
	manifestMetadata.ConfigBlob = manifestData.ConfigBlob
	manifestMetadata.DownloadCount = repoMeta.Statistics[manifestDigest.String()].DownloadCount

	manifestMetadata.Signatures = repodb.ManifestSignatures{}

	if repoMeta.Signatures[manifestDigest.String()] != nil {
		manifestMetadata.Signatures = repoMeta.Signatures[manifestDigest.String()]
	}

	return manifestMetadata, nil
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

func (dwr DBWrapper) SetRepoTag(repo string, tag string, manifestDigest godigest.Digest, mediaType string) error {
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
		Name:       repo,
		Tags:       map[string]repodb.Descriptor{},
		Statistics: map[string]repodb.DescriptorStatistics{},
		Signatures: map[string]repodb.ManifestSignatures{},
	}

	if resp.Item != nil {
		err := attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
		if err != nil {
			return err
		}
	}

	repoMeta.Tags[tag] = repodb.Descriptor{
		Digest:    manifestDigest.String(),
		MediaType: mediaType,
	}

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

func (dwr DBWrapper) IncrementImageDownloads(repo string, reference string) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	manifestDigest := reference

	if !common.ReferenceIsDigest(reference) {
		// search digest for tag
		descriptor, found := repoMeta.Tags[reference]

		if !found {
			return zerr.ErrManifestMetaNotFound
		}

		manifestDigest = descriptor.Digest
	}

	manifestMeta, err := dwr.GetManifestMeta(repo, godigest.Digest(manifestDigest))
	if err != nil {
		return err
	}

	manifestMeta.DownloadCount++

	err = dwr.SetManifestMeta(repo, godigest.Digest(manifestDigest), manifestMeta)

	return err
}

func (dwr DBWrapper) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
	sygMeta repodb.SignatureMetadata,
) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	var (
		manifestSignatures repodb.ManifestSignatures
		found              bool
	)

	if manifestSignatures, found = repoMeta.Signatures[signedManifestDigest.String()]; !found {
		manifestSignatures = repodb.ManifestSignatures{}
	}

	signatureSlice := manifestSignatures[sygMeta.SignatureType]
	if !common.SignatureAlreadyExists(signatureSlice, sygMeta) {
		if sygMeta.SignatureType == repodb.NotationType {
			signatureSlice = append(signatureSlice, repodb.SignatureInfo{
				SignatureManifestDigest: sygMeta.SignatureDigest,
				LayersInfo:              sygMeta.LayersInfo,
			})
		} else if sygMeta.SignatureType == repodb.CosignType {
			signatureSlice = []repodb.SignatureInfo{{
				SignatureManifestDigest: sygMeta.SignatureDigest,
				LayersInfo:              sygMeta.LayersInfo,
			}}
		}
	}

	manifestSignatures[sygMeta.SignatureType] = signatureSlice

	repoMeta.Signatures[signedManifestDigest.String()] = manifestSignatures

	err = dwr.setRepoMeta(repoMeta.Name, repoMeta)

	return err
}

func (dwr DBWrapper) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
	sigMeta repodb.SignatureMetadata,
) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	sigType := sigMeta.SignatureType

	var (
		manifestSignatures repodb.ManifestSignatures
		found              bool
	)

	if manifestSignatures, found = repoMeta.Signatures[signedManifestDigest.String()]; !found {
		return zerr.ErrManifestMetaNotFound
	}

	signatureSlice := manifestSignatures[sigType]

	newSignatureSlice := make([]repodb.SignatureInfo, 0, len(signatureSlice)-1)

	for _, sigDigest := range signatureSlice {
		if sigDigest.SignatureManifestDigest != sigMeta.SignatureDigest {
			newSignatureSlice = append(newSignatureSlice, sigDigest)
		}
	}

	manifestSignatures[sigType] = newSignatureSlice

	repoMeta.Signatures[signedManifestDigest.String()] = manifestSignatures

	err = dwr.setRepoMeta(repoMeta.Name, repoMeta)

	return err
}

func (dwr DBWrapper) GetMultipleRepoMeta(ctx context.Context,
	filter func(repoMeta repodb.RepoMetadata) bool, requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, error) {
	var (
		repoMetaAttributeIterator iterator.AttributesIterator
		pageFinder                repodb.PageFinder
	)

	repoMetaAttributeIterator = iterator.NewBaseDynamoAttributesIterator(
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

	foundRepos, _ := pageFinder.Page()

	return foundRepos, err
}

func (dwr DBWrapper) SearchRepos(ctx context.Context, searchText string, filter repodb.Filter,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, repodb.PageInfo, error) {
	var (
		foundManifestMetadataMap = make(map[string]repodb.ManifestMetadata)
		manifestMetadataMap      = make(map[string]repodb.ManifestMetadata)

		repoMetaAttributeIterator iterator.AttributesIterator
		pageFinder                repodb.PageFinder
		pageInfo                  repodb.PageInfo
	)

	repoMetaAttributeIterator = iterator.NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	pageFinder, err := repodb.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, pageInfo, err
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			// log
			return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, pageInfo, err
		}

		var repoMeta repodb.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, pageInfo, err
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

			for _, descriptor := range repoMeta.Tags {
				var manifestMeta repodb.ManifestMetadata

				manifestMeta, manifestDownloaded := manifestMetadataMap[descriptor.Digest]

				if !manifestDownloaded {
					manifestMeta, err = dwr.GetManifestMeta(repoMeta.Name, godigest.Digest(descriptor.Digest)) //nolint:contextcheck
					if err != nil {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, pageInfo,
							errors.Wrapf(err, "repodb: error while unmarshaling manifest metadata for digest %s", descriptor.Digest)
					}
				}

				// get fields related to filtering
				var configContent ispec.Image

				err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
				if err != nil {
					return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, pageInfo,
						errors.Wrapf(err, "repodb: error while unmarshaling config content for digest %s", descriptor.Digest)
				}

				osSet[configContent.OS] = true
				archSet[configContent.Architecture] = true

				// get fields related to sorting
				repoDownloads += repoMeta.Statistics[descriptor.Digest].DownloadCount

				imageLastUpdated := common.GetImageLastUpdatedTimestamp(configContent)

				if firstImageChecked || repoLastUpdated.Before(imageLastUpdated) {
					repoLastUpdated = imageLastUpdated
					firstImageChecked = false

					isSigned = common.CheckIsSigned(manifestMeta.Signatures)
				}

				manifestMetadataMap[descriptor.Digest] = manifestMeta
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

	foundRepos, pageInfo := pageFinder.Page()

	// keep just the manifestMeta we need
	for _, repoMeta := range foundRepos {
		for _, descriptor := range repoMeta.Tags {
			foundManifestMetadataMap[descriptor.Digest] = manifestMetadataMap[descriptor.Digest]
		}
	}

	return foundRepos, foundManifestMetadataMap, pageInfo, err
}

func (dwr DBWrapper) FilterTags(ctx context.Context, filter repodb.FilterFunc,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	var (
		foundManifestMetadataMap  = make(map[string]repodb.ManifestMetadata)
		manifestMetadataMap       = make(map[string]repodb.ManifestMetadata)
		pageFinder                repodb.PageFinder
		repoMetaAttributeIterator iterator.AttributesIterator
	)

	repoMetaAttributeIterator = iterator.NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
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
		matchedTags := make(map[string]repodb.Descriptor)
		// take all manifestMetas
		for tag, descriptor := range repoMeta.Tags {
			manifestDigest := descriptor.Digest

			matchedTags[tag] = descriptor

			// in case tags reference the same manifest we don't download from DB multiple times
			manifestMeta, manifestExists := manifestMetadataMap[manifestDigest]

			if !manifestExists {
				manifestMeta, err := dwr.GetManifestMeta(repoMeta.Name, godigest.Digest(manifestDigest)) //nolint:contextcheck
				if err != nil {
					return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{},
						errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", manifestDigest)
				}

				var configContent ispec.Image

				err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
				if err != nil {
					return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{},
						errors.Wrapf(err, "repodb: error while unmashaling config for manifest with digest %s", manifestDigest)
				}
			}

			if !filter(repoMeta, manifestMeta) {
				delete(matchedTags, tag)

				continue
			}

			manifestMetadataMap[manifestDigest] = manifestMeta
		}

		if len(matchedTags) == 0 {
			continue
		}

		repoMeta.Tags = matchedTags

		pageFinder.Add(repodb.DetailedRepoMeta{
			RepoMeta: repoMeta,
		})
	}

	foundRepos, _ := pageFinder.Page()

	// keep just the manifestMeta we need
	for _, repoMeta := range foundRepos {
		for _, descriptor := range repoMeta.Tags {
			foundManifestMetadataMap[descriptor.Digest] = manifestMetadataMap[descriptor.Digest]
		}
	}

	return foundRepos, foundManifestMetadataMap, err
}

func (dwr DBWrapper) SearchTags(ctx context.Context, searchText string, filter repodb.Filter,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, repodb.PageInfo, error) {
	var (
		foundManifestMetadataMap  = make(map[string]repodb.ManifestMetadata)
		manifestMetadataMap       = make(map[string]repodb.ManifestMetadata)
		repoMetaAttributeIterator = iterator.NewBaseDynamoAttributesIterator(
			dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
		)

		pageFinder repodb.PageFinder
		pageInfo   repodb.PageInfo
	)

	pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, pageInfo, err
	}

	searchedRepo, searchedTag, err := common.GetRepoTag(searchText)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, pageInfo,
			errors.Wrap(err, "repodb: error while parsing search text, invalid format")
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			// log
			return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, pageInfo, err
		}

		var repoMeta repodb.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, pageInfo, err
		}

		if ok, err := localCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		if repoMeta.Name == searchedRepo {
			matchedTags := make(map[string]repodb.Descriptor)
			// take all manifestMetas
			for tag, descriptor := range repoMeta.Tags {
				if !strings.HasPrefix(tag, searchedTag) {
					continue
				}

				matchedTags[tag] = descriptor

				// in case tags reference the same manifest we don't download from DB multiple times
				if manifestMeta, manifestExists := manifestMetadataMap[descriptor.Digest]; manifestExists {
					manifestMetadataMap[descriptor.Digest] = manifestMeta

					continue
				}

				manifestMeta, err := dwr.GetManifestMeta(repoMeta.Name, godigest.Digest(descriptor.Digest)) //nolint:contextcheck
				if err != nil {
					return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, pageInfo,
						errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", descriptor.Digest)
				}

				var configContent ispec.Image

				err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
				if err != nil {
					return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, pageInfo,
						errors.Wrapf(err, "repodb: error while unmashaling config for manifest with digest %s", descriptor.Digest)
				}

				imageFilterData := repodb.FilterData{
					OsList:   []string{configContent.OS},
					ArchList: []string{configContent.Architecture},
					IsSigned: false,
				}

				if !common.AcceptedByFilter(filter, imageFilterData) {
					delete(matchedTags, tag)
					delete(manifestMetadataMap, descriptor.Digest)

					continue
				}

				manifestMetadataMap[descriptor.Digest] = manifestMeta
			}

			if len(matchedTags) == 0 {
				continue
			}

			repoMeta.Tags = matchedTags

			pageFinder.Add(repodb.DetailedRepoMeta{
				RepoMeta: repoMeta,
			})
		}
	}

	foundRepos, pageInfo := pageFinder.Page()

	// keep just the manifestMeta we need
	for _, repoMeta := range foundRepos {
		for _, descriptor := range repoMeta.Tags {
			foundManifestMetadataMap[descriptor.Digest] = manifestMetadataMap[descriptor.Digest]
		}
	}

	return foundRepos, foundManifestMetadataMap, pageInfo, err
}

func (dwr *DBWrapper) PatchDB() error {
	DBVersion, err := dwr.getDBVersion()
	if err != nil {
		return errors.Wrapf(err, "patching dynamo failed, error retrieving database version")
	}

	if version.GetVersionIndex(DBVersion) == -1 {
		return errors.New("DB has broken format, no version found")
	}

	for patchIndex, patch := range dwr.Patches {
		if patchIndex < version.GetVersionIndex(DBVersion) {
			continue
		}

		tableNames := map[string]string{
			"RepoMetaTablename":     dwr.RepoMetaTablename,
			"ManifestDataTablename": dwr.ManifestDataTablename,
			"VersionTablename":      dwr.VersionTablename,
		}

		err := patch(dwr.Client, tableNames)
		if err != nil {
			return err
		}
	}

	return nil
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

	if err != nil && !strings.Contains(err.Error(), "Table already exists") {
		return err
	}

	return dwr.waitTableToBeCreated(dwr.RepoMetaTablename)
}

func (dwr DBWrapper) deleteRepoMetaTable() error {
	_, err := dwr.Client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
		TableName: aws.String(dwr.RepoMetaTablename),
	})

	if temp := new(types.ResourceNotFoundException); errors.As(err, &temp) {
		return nil
	}

	return dwr.waitTableToBeDeleted(dwr.RepoMetaTablename)
}

func (dwr DBWrapper) ResetRepoMetaTable() error {
	err := dwr.deleteRepoMetaTable()
	if err != nil {
		return err
	}

	return dwr.createRepoMetaTable()
}

func (dwr DBWrapper) waitTableToBeCreated(tableName string) error {
	const maxWaitTime = 20 * time.Second

	waiter := dynamodb.NewTableExistsWaiter(dwr.Client)

	return waiter.Wait(context.Background(), &dynamodb.DescribeTableInput{
		TableName: &tableName,
	}, maxWaitTime)
}

func (dwr DBWrapper) waitTableToBeDeleted(tableName string) error {
	const maxWaitTime = 20 * time.Second

	waiter := dynamodb.NewTableNotExistsWaiter(dwr.Client)

	return waiter.Wait(context.Background(), &dynamodb.DescribeTableInput{
		TableName: &tableName,
	}, maxWaitTime)
}

func (dwr DBWrapper) createManifestDataTable() error {
	_, err := dwr.Client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String(dwr.ManifestDataTablename),
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

	if err != nil && !strings.Contains(err.Error(), "Table already exists") {
		return err
	}

	return dwr.waitTableToBeCreated(dwr.ManifestDataTablename)
}

func (dwr *DBWrapper) createVersionTable() error {
	_, err := dwr.Client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String(dwr.VersionTablename),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("VersionKey"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("VersionKey"),
				KeyType:       types.KeyTypeHash,
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})
	if err != nil {
		if strings.Contains(err.Error(), "Table already exists") {
			return nil
		}

		return err
	}

	err = dwr.waitTableToBeCreated(dwr.VersionTablename)
	if err != nil {
		return err
	}

	if err == nil {
		mdAttributeValue, err := attributevalue.Marshal(version.CurrentVersion)
		if err != nil {
			return err
		}

		_, err = dwr.Client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
			ExpressionAttributeNames: map[string]string{
				"#V": "Version",
			},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":Version": mdAttributeValue,
			},
			Key: map[string]types.AttributeValue{
				"VersionKey": &types.AttributeValueMemberS{
					Value: version.DBVersionKey,
				},
			},
			TableName:        aws.String(dwr.VersionTablename),
			UpdateExpression: aws.String("SET #V = :Version"),
		})

		if err != nil {
			return err
		}
	}

	return nil
}

func (dwr *DBWrapper) getDBVersion() (string, error) {
	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.VersionTablename),
		Key: map[string]types.AttributeValue{
			"VersionKey": &types.AttributeValueMemberS{Value: version.DBVersionKey},
		},
	})
	if err != nil {
		return "", err
	}

	if resp.Item == nil {
		return "", nil
	}

	var version string

	err = attributevalue.Unmarshal(resp.Item["Version"], &version)
	if err != nil {
		return "", err
	}

	return version, nil
}

func (dwr DBWrapper) deleteManifestDataTable() error {
	_, err := dwr.Client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
		TableName: aws.String(dwr.ManifestDataTablename),
	})

	if temp := new(types.ResourceNotFoundException); errors.As(err, &temp) {
		return nil
	}

	return dwr.waitTableToBeDeleted(dwr.ManifestDataTablename)
}

func (dwr DBWrapper) ResetManifestDataTable() error {
	err := dwr.deleteManifestDataTable()
	if err != nil {
		return err
	}

	return dwr.createManifestDataTable()
}
