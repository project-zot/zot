package dynamo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

var errRepodb = errors.New("repodb: error while constructing manifest meta")

type DBWrapper struct {
	Client                *dynamodb.Client
	RepoMetaTablename     string
	IndexDataTablename    string
	ManifestDataTablename string
	ArtifactDataTablename string
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
		IndexDataTablename:    params.IndexDataTablename,
		ArtifactDataTablename: params.ArtifactDataTablename,
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

	err = dynamoWrapper.createArtifactDataTable()
	if err != nil {
		return nil, err
	}

	err = dynamoWrapper.createIndexDataTable()
	if err != nil {
		return nil, err
	}

	// Using the Config value, create the DynamoDB client
	return &dynamoWrapper, nil
}

func (dwr *DBWrapper) SetManifestData(manifestDigest godigest.Digest, manifestData repodb.ManifestData) error {
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

func (dwr *DBWrapper) GetManifestData(manifestDigest godigest.Digest) (repodb.ManifestData, error) {
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

func (dwr *DBWrapper) SetManifestMeta(repo string, manifestDigest godigest.Digest, manifestMeta repodb.ManifestMetadata,
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
			Referrers:  map[string][]repodb.Descriptor{},
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

func (dwr *DBWrapper) GetManifestMeta(repo string, manifestDigest godigest.Digest,
) (repodb.ManifestMetadata, error) { //nolint:contextcheck
	manifestData, err := dwr.GetManifestData(manifestDigest)
	if err != nil {
		if errors.Is(err, zerr.ErrManifestDataNotFound) {
			return repodb.ManifestMetadata{}, zerr.ErrManifestMetaNotFound
		}

		return repodb.ManifestMetadata{},
			fmt.Errorf("%w for manifest '%s' from repo '%s'", errRepodb, manifestDigest, repo)
	}

	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return repodb.ManifestMetadata{}, zerr.ErrManifestMetaNotFound
		}

		return repodb.ManifestMetadata{},
			fmt.Errorf("%w for manifest '%s' from repo '%s'", errRepodb, manifestDigest, repo)
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

func (dwr *DBWrapper) IncrementRepoStars(repo string) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	repoMeta.Stars++

	err = dwr.setRepoMeta(repo, repoMeta)

	return err
}

func (dwr *DBWrapper) DecrementRepoStars(repo string) error {
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

func (dwr *DBWrapper) GetRepoStars(repo string) (int, error) {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return 0, err
	}

	return repoMeta.Stars, nil
}

func (dwr *DBWrapper) SetIndexData(indexDigest godigest.Digest, indexData repodb.IndexData) error {
	indexAttributeValue, err := attributevalue.Marshal(indexData)
	if err != nil {
		return err
	}

	_, err = dwr.Client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#ID": "IndexData",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":IndexData": indexAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"IndexDigest": &types.AttributeValueMemberS{
				Value: indexDigest.String(),
			},
		},
		TableName:        aws.String(dwr.IndexDataTablename),
		UpdateExpression: aws.String("SET #ID = :IndexData"),
	})

	return err
}

func (dwr *DBWrapper) GetIndexData(indexDigest godigest.Digest) (repodb.IndexData, error) {
	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.IndexDataTablename),
		Key: map[string]types.AttributeValue{
			"IndexDigest": &types.AttributeValueMemberS{
				Value: indexDigest.String(),
			},
		},
	})
	if err != nil {
		return repodb.IndexData{}, err
	}

	if resp.Item == nil {
		return repodb.IndexData{}, zerr.ErrRepoMetaNotFound
	}

	var indexData repodb.IndexData

	err = attributevalue.Unmarshal(resp.Item["IndexData"], &indexData)
	if err != nil {
		return repodb.IndexData{}, err
	}

	return indexData, nil
}

func (dwr DBWrapper) SetArtifactData(artifactDigest godigest.Digest, artifactData repodb.ArtifactData) error {
	artifactAttributeValue, err := attributevalue.Marshal(artifactData)
	if err != nil {
		return err
	}

	_, err = dwr.Client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#AD": "ArtifactData",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":ArtifactData": artifactAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"ArtifactDigest": &types.AttributeValueMemberS{
				Value: artifactDigest.String(),
			},
		},
		TableName:        aws.String(dwr.ArtifactDataTablename),
		UpdateExpression: aws.String("SET #AD = :ArtifactData"),
	})

	return err
}

func (dwr DBWrapper) GetArtifactData(artifactDigest godigest.Digest) (repodb.ArtifactData, error) {
	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.ArtifactDataTablename),
		Key: map[string]types.AttributeValue{
			"ArtifactDigest": &types.AttributeValueMemberS{
				Value: artifactDigest.String(),
			},
		},
	})
	if err != nil {
		return repodb.ArtifactData{}, err
	}

	if resp.Item == nil {
		return repodb.ArtifactData{}, zerr.ErrRepoMetaNotFound
	}

	var artifactData repodb.ArtifactData

	err = attributevalue.Unmarshal(resp.Item["ArtifactData"], &artifactData)
	if err != nil {
		return repodb.ArtifactData{}, err
	}

	return artifactData, nil
}

func (dwr DBWrapper) SetReferrer(repo string, referredDigest godigest.Digest, referrer repodb.Descriptor) error {
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
		Referrers:  map[string][]repodb.Descriptor{},
	}

	if resp.Item != nil {
		err := attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
		if err != nil {
			return err
		}
	}

	refferers := repoMeta.Referrers[referredDigest.String()]

	for i := range refferers {
		if refferers[i].Digest == referrer.Digest {
			return nil
		}
	}

	refferers = append(refferers, referrer)

	repoMeta.Referrers[referredDigest.String()] = refferers

	return dwr.setRepoMeta(repo, repoMeta)
}

func (dwr DBWrapper) GetReferrers(repo string, referredDigest godigest.Digest) ([]repodb.Descriptor, error) {
	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.RepoMetaTablename),
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return []repodb.Descriptor{}, err
	}

	repoMeta := repodb.RepoMetadata{
		Name:       repo,
		Tags:       map[string]repodb.Descriptor{},
		Statistics: map[string]repodb.DescriptorStatistics{},
		Signatures: map[string]repodb.ManifestSignatures{},
		Referrers:  map[string][]repodb.Descriptor{},
	}

	if resp.Item != nil {
		err := attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
		if err != nil {
			return []repodb.Descriptor{}, err
		}
	}

	return repoMeta.Referrers[referredDigest.String()], nil
}

func (dwr DBWrapper) DeleteReferrer(repo string, referredDigest godigest.Digest,
	referrerDigest godigest.Digest,
) error {
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
		Referrers:  map[string][]repodb.Descriptor{},
	}

	if resp.Item != nil {
		err := attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
		if err != nil {
			return err
		}
	}

	referrers := repoMeta.Referrers[referredDigest.String()]

	for i := range referrers {
		if referrers[i].Digest == referrerDigest.String() {
			referrers = append(referrers[:i], referrers[i+1:]...)

			break
		}
	}

	repoMeta.Referrers[referredDigest.String()] = referrers

	return dwr.setRepoMeta(repo, repoMeta)
}

func (dwr DBWrapper) GetFilteredReferrersInfo(repo string, referredDigest godigest.Digest,
	artifactTypes []string,
) ([]repodb.ReferrerInfo, error) {
	referrersDescriptors, err := dwr.GetReferrers(repo, referredDigest)
	if err != nil {
		return nil, err
	}

	referrersInfo := []repodb.ReferrerInfo{}

	for _, descriptor := range referrersDescriptors {
		referrerInfo := repodb.ReferrerInfo{}

		switch descriptor.MediaType {
		case ispec.MediaTypeImageManifest:
			manifestData, err := dwr.GetManifestData(godigest.Digest(descriptor.Digest))
			if err != nil {
				dwr.Log.Error().Msgf("repodb: manifest data not found for digest %s", descriptor.Digest)

				continue
			}

			var manifestContent ispec.Manifest

			err = json.Unmarshal(manifestData.ManifestBlob, &manifestContent)
			if err != nil {
				dwr.Log.Error().Err(err).Msgf("repodb: can't unmarhsal manifest for digest %s",
					descriptor.Digest)

				continue
			}

			referrerInfo = repodb.ReferrerInfo{
				Digest:       descriptor.Digest,
				MediaType:    ispec.MediaTypeImageManifest,
				ArtifactType: manifestContent.Config.MediaType,
				Size:         len(manifestData.ManifestBlob),
				Annotations:  manifestContent.Annotations,
			}
		case ispec.MediaTypeArtifactManifest:
			artifactData, err := dwr.GetArtifactData(godigest.Digest(descriptor.Digest))
			if err != nil {
				dwr.Log.Error().Msgf("repodb: artifact data not found for digest %s", descriptor.Digest)

				continue
			}

			manifestContent := ispec.Artifact{}

			err = json.Unmarshal(artifactData.ManifestBlob, &manifestContent)
			if err != nil {
				dwr.Log.Error().Err(err).Msgf("repodb: can't unmarhsal artifact manifest for digest %s", descriptor.Digest)

				continue
			}

			referrerInfo = repodb.ReferrerInfo{
				Digest:       descriptor.Digest,
				MediaType:    manifestContent.MediaType,
				ArtifactType: manifestContent.ArtifactType,
				Size:         len(artifactData.ManifestBlob),
				Annotations:  manifestContent.Annotations,
			}
		}

		if !common.MatchesArtifactTypes(referrerInfo.ArtifactType, artifactTypes) {
			continue
		}

		referrersInfo = append(referrersInfo, referrerInfo)
	}

	return referrersInfo, nil
}

func (dwr *DBWrapper) SetRepoReference(repo string, reference string, manifestDigest godigest.Digest,
	mediaType string,
) error {
	if err := common.ValidateRepoReferenceInput(repo, reference, manifestDigest); err != nil {
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
		Referrers:  map[string][]repodb.Descriptor{},
	}

	if resp.Item != nil {
		err := attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
		if err != nil {
			return err
		}
	}

	if !common.ReferenceIsDigest(reference) {
		repoMeta.Tags[reference] = repodb.Descriptor{
			Digest:    manifestDigest.String(),
			MediaType: mediaType,
		}
	}

	repoMeta.Statistics[manifestDigest.String()] = repodb.DescriptorStatistics{DownloadCount: 0}
	repoMeta.Signatures[manifestDigest.String()] = repodb.ManifestSignatures{}
	repoMeta.Referrers[manifestDigest.String()] = []repodb.Descriptor{}

	err = dwr.setRepoMeta(repo, repoMeta)

	return err
}

func (dwr *DBWrapper) DeleteRepoTag(repo string, tag string) error {
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

func (dwr *DBWrapper) GetRepoMeta(repo string) (repodb.RepoMetadata, error) {
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

func (dwr *DBWrapper) IncrementImageDownloads(repo string, reference string) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	descriptorDigest := reference

	if !common.ReferenceIsDigest(reference) {
		// search digest for tag
		descriptor, found := repoMeta.Tags[reference]

		if !found {
			return zerr.ErrManifestMetaNotFound
		}

		descriptorDigest = descriptor.Digest
	}

	manifestStatistics := repoMeta.Statistics[descriptorDigest]
	manifestStatistics.DownloadCount++
	repoMeta.Statistics[descriptorDigest] = manifestStatistics

	return dwr.setRepoMeta(repo, repoMeta)
}

func (dwr *DBWrapper) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
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

func (dwr *DBWrapper) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
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

func (dwr *DBWrapper) GetMultipleRepoMeta(ctx context.Context,
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

func (dwr *DBWrapper) SearchRepos(ctx context.Context, searchText string, filter repodb.Filter,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
	var (
		manifestMetadataMap       = make(map[string]repodb.ManifestMetadata)
		indexDataMap              = make(map[string]repodb.IndexData)
		repoMetaAttributeIterator iterator.AttributesIterator
		pageFinder                repodb.PageFinder
		pageInfo                  repodb.PageInfo
	)

	repoMetaAttributeIterator = iterator.NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	pageFinder, err := repodb.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
			pageInfo, err
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			// log
			return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
				pageInfo, err
		}

		var repoMeta repodb.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
				pageInfo, err
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
				switch descriptor.MediaType {
				case ispec.MediaTypeImageManifest:
					manifestDigest := descriptor.Digest

					manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifestDigest, //nolint:contextcheck
						manifestMetadataMap)
					if err != nil {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
							pageInfo,
							fmt.Errorf("%w", err)
					}

					manifestFilterData, err := collectImageManifestFilterData(manifestDigest, repoMeta, manifestMeta)
					if err != nil {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
							pageInfo,
							fmt.Errorf("%w", err)
					}

					repoDownloads += manifestFilterData.DownloadCount

					for _, os := range manifestFilterData.OsList {
						osSet[os] = true
					}

					for _, arch := range manifestFilterData.ArchList {
						archSet[arch] = true
					}

					if firstImageChecked || repoLastUpdated.Before(manifestFilterData.LastUpdated) {
						repoLastUpdated = manifestFilterData.LastUpdated
						firstImageChecked = false

						isSigned = manifestFilterData.IsSigned
					}

					manifestMetadataMap[descriptor.Digest] = manifestMeta
				case ispec.MediaTypeImageIndex:
					var indexLastUpdated time.Time

					indexDigest := descriptor.Digest

					indexData, err := dwr.fetchIndexDataWithCheck(indexDigest, indexDataMap) //nolint:contextcheck
					if err != nil {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
							pageInfo,
							fmt.Errorf("%w", err)
					}

					// this also updates manifestMetadataMap
					imageFilterData, err := dwr.collectImageIndexFilterInfo(indexDigest, repoMeta, indexData, //nolint:contextcheck
						manifestMetadataMap)
					if err != nil {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
							pageInfo,
							fmt.Errorf("%w", err)
					}

					for _, arch := range imageFilterData.ArchList {
						archSet[arch] = true
					}

					for _, os := range imageFilterData.OsList {
						osSet[os] = true
					}

					repoDownloads += imageFilterData.DownloadCount

					if repoLastUpdated.Before(imageFilterData.LastUpdated) {
						repoLastUpdated = indexLastUpdated

						isSigned = imageFilterData.IsSigned
					}

					indexDataMap[indexDigest] = indexData
				default:
					dwr.Log.Error().Msgf("Unsupported type: %s", descriptor.MediaType)

					continue
				}
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

	foundManifestMetadataMap, foundindexDataMap, err := filterFoundData(foundRepos, manifestMetadataMap, indexDataMap)

	return foundRepos, foundManifestMetadataMap, foundindexDataMap, pageInfo, err
}

func (dwr *DBWrapper) fetchManifestMetaWithCheck(repoName string, manifestDigest string,
	manifestMetadataMap map[string]repodb.ManifestMetadata,
) (repodb.ManifestMetadata, error) {
	var (
		manifestMeta repodb.ManifestMetadata
		err          error
	)

	manifestMeta, manifestDownloaded := manifestMetadataMap[manifestDigest]

	if !manifestDownloaded {
		manifestMeta, err = dwr.GetManifestMeta(repoName, godigest.Digest(manifestDigest)) //nolint:contextcheck
		if err != nil {
			return repodb.ManifestMetadata{}, err
		}
	}

	return manifestMeta, nil
}

func collectImageManifestFilterData(digest string, repoMeta repodb.RepoMetadata,
	manifestMeta repodb.ManifestMetadata,
) (repodb.FilterData, error) {
	// get fields related to filtering
	var (
		configContent ispec.Image
		osList        []string
		archList      []string
	)

	err := json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
	if err != nil {
		return repodb.FilterData{}, fmt.Errorf("repodb: error while unmarshaling config content %w", err)
	}

	if configContent.OS != "" {
		osList = append(osList, configContent.OS)
	}

	if configContent.Architecture != "" {
		archList = append(archList, configContent.Architecture)
	}

	return repodb.FilterData{
		DownloadCount: repoMeta.Statistics[digest].DownloadCount,
		OsList:        osList,
		ArchList:      archList,
		LastUpdated:   common.GetImageLastUpdatedTimestamp(configContent),
		IsSigned:      common.CheckIsSigned(repoMeta.Signatures[digest]),
	}, nil
}

func (dwr *DBWrapper) fetchIndexDataWithCheck(indexDigest string, indexDataMap map[string]repodb.IndexData,
) (repodb.IndexData, error) {
	var (
		indexData repodb.IndexData
		err       error
	)

	indexData, indexExists := indexDataMap[indexDigest]

	if !indexExists {
		indexData, err = dwr.GetIndexData(godigest.Digest(indexDigest)) //nolint:contextcheck
		if err != nil {
			return repodb.IndexData{},
				fmt.Errorf("repodb: error while unmarshaling index data for digest %s \n%w", indexDigest, err)
		}
	}

	return indexData, err
}

func (dwr *DBWrapper) collectImageIndexFilterInfo(indexDigest string, repoMeta repodb.RepoMetadata,
	indexData repodb.IndexData, manifestMetadataMap map[string]repodb.ManifestMetadata,
) (repodb.FilterData, error) {
	var indexContent ispec.Index

	err := json.Unmarshal(indexData.IndexBlob, &indexContent)
	if err != nil {
		return repodb.FilterData{},
			fmt.Errorf("repodb: error while unmarshaling index content for digest %s %w", indexDigest, err)
	}

	var (
		indexLastUpdated     time.Time
		firstManifestChecked = false
		indexOsList          = []string{}
		indexArchList        = []string{}
	)

	for _, manifest := range indexContent.Manifests {
		manifestDigest := manifest.Digest

		manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifestDigest.String(),
			manifestMetadataMap)
		if err != nil {
			return repodb.FilterData{},
				fmt.Errorf("%w", err)
		}

		manifestFilterData, err := collectImageManifestFilterData(manifestDigest.String(), repoMeta,
			manifestMeta)
		if err != nil {
			return repodb.FilterData{},
				fmt.Errorf("%w", err)
		}

		indexOsList = append(indexOsList, manifestFilterData.OsList...)
		indexArchList = append(indexArchList, manifestFilterData.ArchList...)

		if !firstManifestChecked || indexLastUpdated.Before(manifestFilterData.LastUpdated) {
			indexLastUpdated = manifestFilterData.LastUpdated
			firstManifestChecked = true
		}

		manifestMetadataMap[manifest.Digest.String()] = manifestMeta
	}

	return repodb.FilterData{
		DownloadCount: repoMeta.Statistics[indexDigest].DownloadCount,
		LastUpdated:   indexLastUpdated,
		OsList:        indexOsList,
		ArchList:      indexArchList,
		IsSigned:      common.CheckIsSigned(repoMeta.Signatures[indexDigest]),
	}, nil
}

func (dwr *DBWrapper) FilterTags(ctx context.Context, filter repodb.FilterFunc,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
	var (
		manifestMetadataMap       = make(map[string]repodb.ManifestMetadata)
		indexDataMap              = make(map[string]repodb.IndexData)
		pageFinder                repodb.PageFinder
		repoMetaAttributeIterator iterator.AttributesIterator
		pageInfo                  repodb.PageInfo
	)

	repoMetaAttributeIterator = iterator.NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
			pageInfo, err
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			// log
			return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
				pageInfo, err
		}

		var repoMeta repodb.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
				pageInfo, err
		}

		if ok, err := localCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}
		matchedTags := make(map[string]repodb.Descriptor)
		// take all manifestMetas
		for tag, descriptor := range repoMeta.Tags {
			matchedTags[tag] = descriptor

			switch descriptor.MediaType {
			case ispec.MediaTypeImageManifest:
				manifestDigest := descriptor.Digest

				manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifestDigest, //nolint:contextcheck
					manifestMetadataMap)
				if err != nil {
					return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
						pageInfo,
						fmt.Errorf("repodb: error while unmashaling manifest metadata for digest %s \n%w", manifestDigest, err)
				}

				if !filter(repoMeta, manifestMeta) {
					delete(matchedTags, tag)

					continue
				}

				manifestMetadataMap[manifestDigest] = manifestMeta
			case ispec.MediaTypeImageIndex:
				indexDigest := descriptor.Digest

				indexData, err := dwr.fetchIndexDataWithCheck(indexDigest, indexDataMap) //nolint:contextcheck
				if err != nil {
					return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
						pageInfo,
						fmt.Errorf("repodb: error while getting index data for digest %s %w", indexDigest, err)
				}

				var indexContent ispec.Index

				err = json.Unmarshal(indexData.IndexBlob, &indexContent)
				if err != nil {
					return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
						pageInfo,
						fmt.Errorf("repodb: error while unmashaling index content for digest %s %w", indexDigest, err)
				}

				manifestHasBeenMatched := false

				for _, manifest := range indexContent.Manifests {
					manifestDigest := manifest.Digest.String()

					manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifestDigest, //nolint:contextcheck
						manifestMetadataMap)
					if err != nil {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
							pageInfo,
							fmt.Errorf("%w repodb: error while getting manifest data for digest %s", err, manifestDigest)
					}

					manifestMetadataMap[manifestDigest] = manifestMeta

					if filter(repoMeta, manifestMeta) {
						manifestHasBeenMatched = true
					}
				}

				if !manifestHasBeenMatched {
					delete(matchedTags, tag)

					for _, manifest := range indexContent.Manifests {
						delete(manifestMetadataMap, manifest.Digest.String())
					}

					continue
				}

				indexDataMap[indexDigest] = indexData
			default:
				dwr.Log.Error().Msgf("Unsupported type: %s", descriptor.MediaType)

				continue
			}
		}

		if len(matchedTags) == 0 {
			continue
		}

		repoMeta.Tags = matchedTags

		pageFinder.Add(repodb.DetailedRepoMeta{
			RepoMeta: repoMeta,
		})
	}

	foundRepos, pageInfo := pageFinder.Page()

	foundManifestMetadataMap, foundindexDataMap, err := filterFoundData(foundRepos, manifestMetadataMap, indexDataMap)

	return foundRepos, foundManifestMetadataMap, foundindexDataMap, pageInfo, err
}

func (dwr *DBWrapper) SearchTags(ctx context.Context, searchText string, filter repodb.Filter,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
	var (
		manifestMetadataMap       = make(map[string]repodb.ManifestMetadata)
		indexDataMap              = make(map[string]repodb.IndexData)
		repoMetaAttributeIterator = iterator.NewBaseDynamoAttributesIterator(
			dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
		)

		pageFinder repodb.PageFinder
		pageInfo   repodb.PageInfo
	)

	pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
			pageInfo, err
	}

	searchedRepo, searchedTag, err := common.GetRepoTag(searchText)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
			pageInfo,
			fmt.Errorf("repodb: error while parsing search text, invalid format %w", err)
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			// log
			return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
				pageInfo, err
		}

		var repoMeta repodb.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
				pageInfo, err
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

				switch descriptor.MediaType {
				case ispec.MediaTypeImageManifest:
					manifestDigest := descriptor.Digest

					manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifestDigest, //nolint:contextcheck
						manifestMetadataMap)
					if err != nil {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
							pageInfo,
							fmt.Errorf("repodb: error while unmashaling manifest metadata for digest %s %w", descriptor.Digest, err)
					}

					imageFilterData, err := collectImageManifestFilterData(manifestDigest, repoMeta, manifestMeta)
					if err != nil {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
							pageInfo,
							fmt.Errorf("%w", err)
					}

					if !common.AcceptedByFilter(filter, imageFilterData) {
						delete(matchedTags, tag)

						continue
					}

					manifestMetadataMap[descriptor.Digest] = manifestMeta
				case ispec.MediaTypeImageIndex:
					indexDigest := descriptor.Digest

					indexData, err := dwr.fetchIndexDataWithCheck(indexDigest, indexDataMap) //nolint:contextcheck
					if err != nil {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
							pageInfo,
							fmt.Errorf("%w", err)
					}

					var indexContent ispec.Index

					err = json.Unmarshal(indexData.IndexBlob, &indexContent)
					if err != nil {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
							pageInfo,
							fmt.Errorf("repodb: error while unmashaling index content for digest %s %w", indexDigest, err)
					}

					manifestHasBeenMatched := false

					for _, manifest := range indexContent.Manifests {
						manifestDigest := manifest.Digest.String()

						manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifestDigest, //nolint:contextcheck
							manifestMetadataMap)
						if err != nil {
							return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
								pageInfo,
								fmt.Errorf("%w", err)
						}

						manifestFilterData, err := collectImageManifestFilterData(manifestDigest, repoMeta, manifestMeta)
						if err != nil {
							return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
								pageInfo,
								fmt.Errorf("%w", err)
						}

						manifestMetadataMap[manifestDigest] = manifestMeta

						if common.AcceptedByFilter(filter, manifestFilterData) {
							manifestHasBeenMatched = true
						}
					}

					if !manifestHasBeenMatched {
						delete(matchedTags, tag)

						for _, manifest := range indexContent.Manifests {
							delete(manifestMetadataMap, manifest.Digest.String())
						}

						continue
					}

					indexDataMap[indexDigest] = indexData
				default:
					dwr.Log.Error().Msgf("Unsupported type: %s", descriptor.MediaType)

					continue
				}
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

	foundManifestMetadataMap, foundindexDataMap, err := filterFoundData(foundRepos, manifestMetadataMap, indexDataMap)

	return foundRepos, foundManifestMetadataMap, foundindexDataMap, pageInfo, err
}

func filterFoundData(foundRepos []repodb.RepoMetadata, manifestMetadataMap map[string]repodb.ManifestMetadata,
	indexDataMap map[string]repodb.IndexData,
) (map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, error) {
	var (
		foundManifestMetadataMap = make(map[string]repodb.ManifestMetadata)
		foundindexDataMap        = make(map[string]repodb.IndexData)
	)

	// keep just the manifestMeta we need
	for _, repoMeta := range foundRepos {
		for _, descriptor := range repoMeta.Tags {
			switch descriptor.MediaType {
			case ispec.MediaTypeImageManifest:
				foundManifestMetadataMap[descriptor.Digest] = manifestMetadataMap[descriptor.Digest]
			case ispec.MediaTypeImageIndex:
				indexData := indexDataMap[descriptor.Digest]

				var indexContent ispec.Index

				err := json.Unmarshal(indexData.IndexBlob, &indexContent)
				if err != nil {
					return map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
						fmt.Errorf("repodb: error while getting manifest data for digest %s %w", descriptor.Digest, err)
				}

				for _, manifestDescriptor := range indexContent.Manifests {
					manifestDigest := manifestDescriptor.Digest.String()

					foundManifestMetadataMap[manifestDigest] = manifestMetadataMap[manifestDigest]
				}

				foundindexDataMap[descriptor.Digest] = indexData
			default:
			}
		}
	}

	return foundManifestMetadataMap, foundindexDataMap, nil
}

func (dwr *DBWrapper) PatchDB() error {
	DBVersion, err := dwr.getDBVersion()
	if err != nil {
		return fmt.Errorf("patching dynamo failed, error retrieving database version %w", err)
	}

	if version.GetVersionIndex(DBVersion) == -1 {
		return fmt.Errorf("DB has broken format, no version found %w", err)
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

func (dwr *DBWrapper) setRepoMeta(repo string, repoMeta repodb.RepoMetadata) error {
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

func (dwr *DBWrapper) createRepoMetaTable() error {
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

func (dwr *DBWrapper) deleteRepoMetaTable() error {
	_, err := dwr.Client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
		TableName: aws.String(dwr.RepoMetaTablename),
	})

	if temp := new(types.ResourceNotFoundException); errors.As(err, &temp) {
		return nil
	}

	return dwr.waitTableToBeDeleted(dwr.RepoMetaTablename)
}

func (dwr *DBWrapper) ResetRepoMetaTable() error {
	err := dwr.deleteRepoMetaTable()
	if err != nil {
		return err
	}

	return dwr.createRepoMetaTable()
}

func (dwr *DBWrapper) waitTableToBeCreated(tableName string) error {
	const maxWaitTime = 20 * time.Second

	waiter := dynamodb.NewTableExistsWaiter(dwr.Client)

	return waiter.Wait(context.Background(), &dynamodb.DescribeTableInput{
		TableName: &tableName,
	}, maxWaitTime)
}

func (dwr *DBWrapper) waitTableToBeDeleted(tableName string) error {
	const maxWaitTime = 20 * time.Second

	waiter := dynamodb.NewTableNotExistsWaiter(dwr.Client)

	return waiter.Wait(context.Background(), &dynamodb.DescribeTableInput{
		TableName: &tableName,
	}, maxWaitTime)
}

func (dwr *DBWrapper) createManifestDataTable() error {
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

func (dwr *DBWrapper) createIndexDataTable() error {
	_, err := dwr.Client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String(dwr.IndexDataTablename),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("IndexDigest"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("IndexDigest"),
				KeyType:       types.KeyTypeHash,
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})

	if err != nil && strings.Contains(err.Error(), "Table already exists") {
		return nil
	}

	return dwr.waitTableToBeCreated(dwr.IndexDataTablename)
}

func (dwr DBWrapper) createArtifactDataTable() error {
	_, err := dwr.Client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String(dwr.ArtifactDataTablename),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("ArtifactDigest"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("ArtifactDigest"),
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

func (dwr *DBWrapper) deleteManifestDataTable() error {
	_, err := dwr.Client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
		TableName: aws.String(dwr.ManifestDataTablename),
	})

	if temp := new(types.ResourceNotFoundException); errors.As(err, &temp) {
		return nil
	}

	return dwr.waitTableToBeDeleted(dwr.ManifestDataTablename)
}

func (dwr *DBWrapper) ResetManifestDataTable() error {
	err := dwr.deleteManifestDataTable()
	if err != nil {
		return err
	}

	return dwr.createManifestDataTable()
}
