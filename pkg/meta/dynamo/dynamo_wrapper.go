package dynamo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/common"
	"zotregistry.io/zot/pkg/meta/pagination"
	"zotregistry.io/zot/pkg/meta/signatures"
	metaTypes "zotregistry.io/zot/pkg/meta/types" //nolint:go-staticcheck
	"zotregistry.io/zot/pkg/meta/version"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
)

var errRepodb = errors.New("repodb: error while constructing manifest meta")

type DBWrapper struct {
	Client                *dynamodb.Client
	RepoMetaTablename     string
	IndexDataTablename    string
	ManifestDataTablename string
	UserDataTablename     string
	VersionTablename      string
	Patches               []func(client *dynamodb.Client, tableNames map[string]string) error
	Log                   log.Logger
}

func NewDynamoDBWrapper(client *dynamodb.Client, params DBDriverParameters, log log.Logger) (*DBWrapper, error) {
	dynamoWrapper := DBWrapper{
		Client:                client,
		RepoMetaTablename:     params.RepoMetaTablename,
		ManifestDataTablename: params.ManifestDataTablename,
		IndexDataTablename:    params.IndexDataTablename,
		VersionTablename:      params.VersionTablename,
		UserDataTablename:     params.UserDataTablename,
		Patches:               version.GetDynamoDBPatches(),
		Log:                   log,
	}

	err := dynamoWrapper.createVersionTable()
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

	err = dynamoWrapper.createIndexDataTable()
	if err != nil {
		return nil, err
	}

	err = dynamoWrapper.createUserDataTable()
	if err != nil {
		return nil, err
	}

	// Using the Config value, create the DynamoDB client
	return &dynamoWrapper, nil
}

func (dwr *DBWrapper) SetManifestData(manifestDigest godigest.Digest, manifestData metaTypes.ManifestData) error {
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

func (dwr *DBWrapper) GetManifestData(manifestDigest godigest.Digest) (metaTypes.ManifestData, error) {
	resp, err := dwr.Client.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.ManifestDataTablename),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: manifestDigest.String()},
		},
	})
	if err != nil {
		return metaTypes.ManifestData{}, err
	}

	if resp.Item == nil {
		return metaTypes.ManifestData{}, zerr.ErrManifestDataNotFound
	}

	var manifestData metaTypes.ManifestData

	err = attributevalue.Unmarshal(resp.Item["ManifestData"], &manifestData)
	if err != nil {
		return metaTypes.ManifestData{}, err
	}

	return manifestData, nil
}

func (dwr *DBWrapper) SetManifestMeta(repo string, manifestDigest godigest.Digest,
	manifestMeta metaTypes.ManifestMetadata,
) error {
	if manifestMeta.Signatures == nil {
		manifestMeta.Signatures = metaTypes.ManifestSignatures{}
	}

	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		if !errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return err
		}

		repoMeta = metaTypes.RepoMetadata{
			Name:       repo,
			Tags:       map[string]metaTypes.Descriptor{},
			Statistics: map[string]metaTypes.DescriptorStatistics{},
			Signatures: map[string]metaTypes.ManifestSignatures{},
			Referrers:  map[string][]metaTypes.ReferrerInfo{},
		}
	}

	err = dwr.SetManifestData(manifestDigest, metaTypes.ManifestData{
		ManifestBlob: manifestMeta.ManifestBlob,
		ConfigBlob:   manifestMeta.ConfigBlob,
	})
	if err != nil {
		return err
	}

	updatedRepoMeta := common.UpdateManifestMeta(repoMeta, manifestDigest, manifestMeta)

	err = dwr.SetRepoMeta(repo, updatedRepoMeta)
	if err != nil {
		return err
	}

	return err
}

func (dwr *DBWrapper) GetManifestMeta(repo string, manifestDigest godigest.Digest,
) (metaTypes.ManifestMetadata, error) { //nolint:contextcheck
	manifestData, err := dwr.GetManifestData(manifestDigest)
	if err != nil {
		if errors.Is(err, zerr.ErrManifestDataNotFound) {
			return metaTypes.ManifestMetadata{}, zerr.ErrManifestMetaNotFound
		}

		return metaTypes.ManifestMetadata{},
			fmt.Errorf("%w for manifest '%s' from repo '%s'", errRepodb, manifestDigest, repo)
	}

	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return metaTypes.ManifestMetadata{}, zerr.ErrManifestMetaNotFound
		}

		return metaTypes.ManifestMetadata{},
			fmt.Errorf("%w for manifest '%s' from repo '%s'", errRepodb, manifestDigest, repo)
	}

	manifestMetadata := metaTypes.ManifestMetadata{}

	manifestMetadata.ManifestBlob = manifestData.ManifestBlob
	manifestMetadata.ConfigBlob = manifestData.ConfigBlob
	manifestMetadata.DownloadCount = repoMeta.Statistics[manifestDigest.String()].DownloadCount

	manifestMetadata.Signatures = metaTypes.ManifestSignatures{}

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

	err = dwr.SetRepoMeta(repo, repoMeta)

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

	err = dwr.SetRepoMeta(repo, repoMeta)

	return err
}

func (dwr *DBWrapper) GetRepoStars(repo string) (int, error) {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return 0, err
	}

	return repoMeta.Stars, nil
}

func (dwr *DBWrapper) SetIndexData(indexDigest godigest.Digest, indexData metaTypes.IndexData) error {
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

func (dwr *DBWrapper) GetIndexData(indexDigest godigest.Digest) (metaTypes.IndexData, error) {
	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.IndexDataTablename),
		Key: map[string]types.AttributeValue{
			"IndexDigest": &types.AttributeValueMemberS{
				Value: indexDigest.String(),
			},
		},
	})
	if err != nil {
		return metaTypes.IndexData{}, err
	}

	if resp.Item == nil {
		return metaTypes.IndexData{}, zerr.ErrRepoMetaNotFound
	}

	var indexData metaTypes.IndexData

	err = attributevalue.Unmarshal(resp.Item["IndexData"], &indexData)
	if err != nil {
		return metaTypes.IndexData{}, err
	}

	return indexData, nil
}

func (dwr DBWrapper) SetReferrer(repo string, referredDigest godigest.Digest, referrer metaTypes.ReferrerInfo) error {
	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.RepoMetaTablename),
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return err
	}

	repoMeta := metaTypes.RepoMetadata{
		Name:       repo,
		Tags:       map[string]metaTypes.Descriptor{},
		Statistics: map[string]metaTypes.DescriptorStatistics{},
		Signatures: map[string]metaTypes.ManifestSignatures{},
		Referrers:  map[string][]metaTypes.ReferrerInfo{},
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

	return dwr.SetRepoMeta(repo, repoMeta)
}

func (dwr DBWrapper) GetReferrers(repo string, referredDigest godigest.Digest) ([]metaTypes.ReferrerInfo, error) {
	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.RepoMetaTablename),
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return []metaTypes.ReferrerInfo{}, err
	}

	repoMeta := metaTypes.RepoMetadata{
		Name:       repo,
		Tags:       map[string]metaTypes.Descriptor{},
		Statistics: map[string]metaTypes.DescriptorStatistics{},
		Signatures: map[string]metaTypes.ManifestSignatures{},
		Referrers:  map[string][]metaTypes.ReferrerInfo{},
	}

	if resp.Item != nil {
		err := attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
		if err != nil {
			return []metaTypes.ReferrerInfo{}, err
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

	repoMeta := metaTypes.RepoMetadata{
		Name:       repo,
		Tags:       map[string]metaTypes.Descriptor{},
		Statistics: map[string]metaTypes.DescriptorStatistics{},
		Signatures: map[string]metaTypes.ManifestSignatures{},
		Referrers:  map[string][]metaTypes.ReferrerInfo{},
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

	return dwr.SetRepoMeta(repo, repoMeta)
}

func (dwr DBWrapper) GetReferrersInfo(repo string, referredDigest godigest.Digest,
	artifactTypes []string,
) ([]metaTypes.ReferrerInfo, error) {
	referrersInfo, err := dwr.GetReferrers(repo, referredDigest)
	if err != nil {
		return nil, err
	}

	filteredResults := make([]metaTypes.ReferrerInfo, 0, len(referrersInfo))

	for _, referrerInfo := range referrersInfo {
		if !common.MatchesArtifactTypes(referrerInfo.ArtifactType, artifactTypes) {
			continue
		}

		filteredResults = append(filteredResults, referrerInfo)
	}

	return filteredResults, nil
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

	repoMeta := metaTypes.RepoMetadata{
		Name:       repo,
		Tags:       map[string]metaTypes.Descriptor{},
		Statistics: map[string]metaTypes.DescriptorStatistics{},
		Signatures: map[string]metaTypes.ManifestSignatures{},
		Referrers:  map[string][]metaTypes.ReferrerInfo{},
	}

	if resp.Item != nil {
		err := attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
		if err != nil {
			return err
		}
	}

	if !common.ReferenceIsDigest(reference) {
		repoMeta.Tags[reference] = metaTypes.Descriptor{
			Digest:    manifestDigest.String(),
			MediaType: mediaType,
		}
	}

	if _, ok := repoMeta.Statistics[manifestDigest.String()]; !ok {
		repoMeta.Statistics[manifestDigest.String()] = metaTypes.DescriptorStatistics{DownloadCount: 0}
	}

	if _, ok := repoMeta.Signatures[manifestDigest.String()]; !ok {
		repoMeta.Signatures[manifestDigest.String()] = metaTypes.ManifestSignatures{}
	}

	if _, ok := repoMeta.Referrers[manifestDigest.String()]; !ok {
		repoMeta.Referrers[manifestDigest.String()] = []metaTypes.ReferrerInfo{}
	}

	err = dwr.SetRepoMeta(repo, repoMeta)

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

	var repoMeta metaTypes.RepoMetadata

	err = attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
	if err != nil {
		return err
	}

	delete(repoMeta.Tags, tag)

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

func (dwr *DBWrapper) GetRepoMeta(repo string) (metaTypes.RepoMetadata, error) {
	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.RepoMetaTablename),
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return metaTypes.RepoMetadata{}, err
	}

	if resp.Item == nil {
		return metaTypes.RepoMetadata{}, zerr.ErrRepoMetaNotFound
	}

	var repoMeta metaTypes.RepoMetadata

	err = attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
	if err != nil {
		return metaTypes.RepoMetadata{}, err
	}

	return repoMeta, nil
}

func (dwr *DBWrapper) GetUserRepoMeta(ctx context.Context, repo string) (metaTypes.RepoMetadata, error) {
	resp, err := dwr.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(dwr.RepoMetaTablename),
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return metaTypes.RepoMetadata{}, err
	}

	if resp.Item == nil {
		return metaTypes.RepoMetadata{}, zerr.ErrRepoMetaNotFound
	}

	var repoMeta metaTypes.RepoMetadata

	err = attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
	if err != nil {
		return metaTypes.RepoMetadata{}, err
	}

	userMeta, err := dwr.GetUserMeta(ctx)
	if err != nil {
		return metaTypes.RepoMetadata{}, err
	}

	repoMeta.IsBookmarked = zcommon.Contains(userMeta.BookmarkedRepos, repo)
	repoMeta.IsStarred = zcommon.Contains(userMeta.StarredRepos, repo)

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

	return dwr.SetRepoMeta(repo, repoMeta)
}

func (dwr *DBWrapper) UpdateSignaturesValidity(repo string, manifestDigest godigest.Digest) error {
	return nil
}

func (dwr *DBWrapper) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
	sygMeta metaTypes.SignatureMetadata,
) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			repoMeta = metaTypes.RepoMetadata{
				Name:       repo,
				Tags:       map[string]metaTypes.Descriptor{},
				Statistics: map[string]metaTypes.DescriptorStatistics{},
				Signatures: map[string]metaTypes.ManifestSignatures{
					signedManifestDigest.String(): {
						sygMeta.SignatureType: []metaTypes.SignatureInfo{
							{
								SignatureManifestDigest: sygMeta.SignatureDigest,
								LayersInfo:              sygMeta.LayersInfo,
							},
						},
					},
				},
				Referrers: map[string][]metaTypes.ReferrerInfo{},
			}

			return dwr.SetRepoMeta(repo, repoMeta)
		}

		return err
	}

	var (
		manifestSignatures metaTypes.ManifestSignatures
		found              bool
	)

	if manifestSignatures, found = repoMeta.Signatures[signedManifestDigest.String()]; !found {
		manifestSignatures = metaTypes.ManifestSignatures{}
	}

	signatureSlice := manifestSignatures[sygMeta.SignatureType]
	if !common.SignatureAlreadyExists(signatureSlice, sygMeta) {
		if sygMeta.SignatureType == signatures.NotationSignature {
			signatureSlice = append(signatureSlice, metaTypes.SignatureInfo{
				SignatureManifestDigest: sygMeta.SignatureDigest,
				LayersInfo:              sygMeta.LayersInfo,
			})
		} else if sygMeta.SignatureType == signatures.CosignSignature {
			signatureSlice = []metaTypes.SignatureInfo{{
				SignatureManifestDigest: sygMeta.SignatureDigest,
				LayersInfo:              sygMeta.LayersInfo,
			}}
		}
	}

	manifestSignatures[sygMeta.SignatureType] = signatureSlice

	repoMeta.Signatures[signedManifestDigest.String()] = manifestSignatures

	return dwr.SetRepoMeta(repoMeta.Name, repoMeta)
}

func (dwr *DBWrapper) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
	sigMeta metaTypes.SignatureMetadata,
) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	sigType := sigMeta.SignatureType

	var (
		manifestSignatures metaTypes.ManifestSignatures
		found              bool
	)

	if manifestSignatures, found = repoMeta.Signatures[signedManifestDigest.String()]; !found {
		return zerr.ErrManifestMetaNotFound
	}

	signatureSlice := manifestSignatures[sigType]

	newSignatureSlice := make([]metaTypes.SignatureInfo, 0, len(signatureSlice)-1)

	for _, sigDigest := range signatureSlice {
		if sigDigest.SignatureManifestDigest != sigMeta.SignatureDigest {
			newSignatureSlice = append(newSignatureSlice, sigDigest)
		}
	}

	manifestSignatures[sigType] = newSignatureSlice

	repoMeta.Signatures[signedManifestDigest.String()] = manifestSignatures

	err = dwr.SetRepoMeta(repoMeta.Name, repoMeta)

	return err
}

func (dwr *DBWrapper) GetMultipleRepoMeta(ctx context.Context,
	filter func(repoMeta metaTypes.RepoMetadata) bool, requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, error) {
	var (
		repoMetaAttributeIterator AttributesIterator
		pageFinder                pagination.PageFinder
	)

	repoMetaAttributeIterator = NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	pageFinder, err := pagination.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return nil, err
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			// log
			return []metaTypes.RepoMetadata{}, err
		}

		var repoMeta metaTypes.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []metaTypes.RepoMetadata{}, err
		}

		if ok, err := localCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		if filter(repoMeta) {
			pageFinder.Add(metaTypes.DetailedRepoMeta{
				RepoMetadata: repoMeta,
			})
		}
	}

	foundRepos, _ := pageFinder.Page()

	return foundRepos, err
}

func (dwr *DBWrapper) SearchRepos(ctx context.Context, searchText string, filter metaTypes.Filter,
	requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData,
	zcommon.PageInfo, error,
) {
	var (
		manifestMetadataMap       = make(map[string]metaTypes.ManifestMetadata)
		indexDataMap              = make(map[string]metaTypes.IndexData)
		repoMetaAttributeIterator AttributesIterator
		pageFinder                pagination.PageFinder
		pageInfo                  zcommon.PageInfo

		userBookmarks = getUserBookmarks(ctx, dwr)
		userStars     = getUserStars(ctx, dwr)
	)

	repoMetaAttributeIterator = NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	pageFinder, err := pagination.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
			pageInfo, err
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
				pageInfo, err
		}

		var repoMeta metaTypes.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
				pageInfo, err
		}

		if ok, err := localCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		rank := common.RankRepoName(searchText, repoMeta.Name)
		if rank == -1 {
			continue
		}

		repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repoMeta.Name)
		repoMeta.IsStarred = zcommon.Contains(userStars, repoMeta.Name)

		var (
			repoDownloads   = 0
			repoLastUpdated = time.Time{}
			osSet           = map[string]bool{}
			archSet         = map[string]bool{}
			noImageChecked  = true
			isSigned        = false
		)

		for _, descriptor := range repoMeta.Tags {
			switch descriptor.MediaType {
			case ispec.MediaTypeImageManifest:
				manifestDigest := descriptor.Digest

				manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifestDigest, //nolint:contextcheck
					manifestMetadataMap)
				if err != nil {
					return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
						pageInfo,
						fmt.Errorf("%w", err)
				}

				manifestFilterData, err := collectImageManifestFilterData(manifestDigest, repoMeta, manifestMeta)
				if err != nil {
					return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
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

				repoLastUpdated, noImageChecked, isSigned = common.CheckImageLastUpdated(repoLastUpdated, isSigned,
					noImageChecked, manifestFilterData)

				manifestMetadataMap[descriptor.Digest] = manifestMeta
			case ispec.MediaTypeImageIndex:
				indexDigest := descriptor.Digest

				indexData, err := dwr.fetchIndexDataWithCheck(indexDigest, indexDataMap) //nolint:contextcheck
				if err != nil {
					return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
						pageInfo,
						fmt.Errorf("%w", err)
				}

				// this also updates manifestMetadataMap
				indexFilterData, err := dwr.collectImageIndexFilterInfo(indexDigest, repoMeta, indexData, //nolint:contextcheck
					manifestMetadataMap)
				if err != nil {
					return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
						pageInfo,
						fmt.Errorf("%w", err)
				}

				for _, arch := range indexFilterData.ArchList {
					archSet[arch] = true
				}

				for _, os := range indexFilterData.OsList {
					osSet[os] = true
				}

				repoDownloads += indexFilterData.DownloadCount

				repoLastUpdated, noImageChecked, isSigned = common.CheckImageLastUpdated(repoLastUpdated, isSigned,
					noImageChecked, indexFilterData)

				indexDataMap[indexDigest] = indexData
			default:
				dwr.Log.Error().Str("mediaType", descriptor.MediaType).Msg("Unsupported media type")

				continue
			}
		}

		repoFilterData := metaTypes.FilterData{
			OsList:        common.GetMapKeys(osSet),
			ArchList:      common.GetMapKeys(archSet),
			LastUpdated:   repoLastUpdated,
			DownloadCount: repoDownloads,
			IsSigned:      isSigned,
		}

		if !common.AcceptedByFilter(filter, repoFilterData) {
			continue
		}

		pageFinder.Add(metaTypes.DetailedRepoMeta{
			RepoMetadata: repoMeta,
			Rank:         rank,
			Downloads:    repoDownloads,
			UpdateTime:   repoLastUpdated,
		})
	}

	foundRepos, pageInfo := pageFinder.Page()

	foundManifestMetadataMap, foundindexDataMap, err := common.FilterDataByRepo(foundRepos, manifestMetadataMap,
		indexDataMap)

	return foundRepos, foundManifestMetadataMap, foundindexDataMap, pageInfo, err
}

func getUserStars(ctx context.Context, dwr *DBWrapper) []string {
	starredRepos, err := dwr.GetStarredRepos(ctx)
	if err != nil {
		return []string{}
	}

	return starredRepos
}

func getUserBookmarks(ctx context.Context, dwr *DBWrapper) []string {
	bookmarkedRepos, err := dwr.GetBookmarkedRepos(ctx)
	if err != nil {
		return []string{}
	}

	return bookmarkedRepos
}

func (dwr *DBWrapper) fetchManifestMetaWithCheck(repoName string, manifestDigest string,
	manifestMetadataMap map[string]metaTypes.ManifestMetadata,
) (metaTypes.ManifestMetadata, error) {
	var (
		manifestMeta metaTypes.ManifestMetadata
		err          error
	)

	manifestMeta, manifestDownloaded := manifestMetadataMap[manifestDigest]

	if !manifestDownloaded {
		manifestMeta, err = dwr.GetManifestMeta(repoName, godigest.Digest(manifestDigest)) //nolint:contextcheck
		if err != nil {
			return metaTypes.ManifestMetadata{}, err
		}
	}

	return manifestMeta, nil
}

func collectImageManifestFilterData(digest string, repoMeta metaTypes.RepoMetadata,
	manifestMeta metaTypes.ManifestMetadata,
) (metaTypes.FilterData, error) {
	// get fields related to filtering
	var (
		configContent ispec.Image
		osList        []string
		archList      []string
	)

	err := json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
	if err != nil {
		return metaTypes.FilterData{}, fmt.Errorf("repodb: error while unmarshaling config content %w", err)
	}

	if configContent.OS != "" {
		osList = append(osList, configContent.OS)
	}

	if configContent.Architecture != "" {
		archList = append(archList, configContent.Architecture)
	}

	return metaTypes.FilterData{
		DownloadCount: repoMeta.Statistics[digest].DownloadCount,
		OsList:        osList,
		ArchList:      archList,
		LastUpdated:   common.GetImageLastUpdatedTimestamp(configContent),
		IsSigned:      common.CheckIsSigned(repoMeta.Signatures[digest]),
	}, nil
}

func (dwr *DBWrapper) fetchIndexDataWithCheck(indexDigest string, indexDataMap map[string]metaTypes.IndexData,
) (metaTypes.IndexData, error) {
	var (
		indexData metaTypes.IndexData
		err       error
	)

	indexData, indexExists := indexDataMap[indexDigest]

	if !indexExists {
		indexData, err = dwr.GetIndexData(godigest.Digest(indexDigest)) //nolint:contextcheck
		if err != nil {
			return metaTypes.IndexData{},
				fmt.Errorf("repodb: error while unmarshaling index data for digest %s \n%w", indexDigest, err)
		}
	}

	return indexData, err
}

func (dwr *DBWrapper) collectImageIndexFilterInfo(indexDigest string, repoMeta metaTypes.RepoMetadata,
	indexData metaTypes.IndexData, manifestMetadataMap map[string]metaTypes.ManifestMetadata,
) (metaTypes.FilterData, error) {
	var indexContent ispec.Index

	err := json.Unmarshal(indexData.IndexBlob, &indexContent)
	if err != nil {
		return metaTypes.FilterData{},
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
			return metaTypes.FilterData{},
				fmt.Errorf("%w", err)
		}

		manifestFilterData, err := collectImageManifestFilterData(manifestDigest.String(), repoMeta,
			manifestMeta)
		if err != nil {
			return metaTypes.FilterData{},
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

	return metaTypes.FilterData{
		DownloadCount: repoMeta.Statistics[indexDigest].DownloadCount,
		LastUpdated:   indexLastUpdated,
		OsList:        indexOsList,
		ArchList:      indexArchList,
		IsSigned:      common.CheckIsSigned(repoMeta.Signatures[indexDigest]),
	}, nil
}

func (dwr *DBWrapper) FilterTags(ctx context.Context, filter metaTypes.FilterFunc,
	requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData, zcommon.PageInfo,
	error,
) {
	var (
		manifestMetadataMap       = make(map[string]metaTypes.ManifestMetadata)
		indexDataMap              = make(map[string]metaTypes.IndexData)
		repoMetaAttributeIterator AttributesIterator
		pageFinder                pagination.PageFinder
		pageInfo                  zcommon.PageInfo
		userBookmarks             = getUserBookmarks(ctx, dwr)
		userStars                 = getUserStars(ctx, dwr)
	)

	repoMetaAttributeIterator = NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	pageFinder, err := pagination.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
			pageInfo, err
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
				pageInfo, err
		}

		var repoMeta metaTypes.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
				pageInfo, err
		}

		if ok, err := localCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repoMeta.Name)
		repoMeta.IsStarred = zcommon.Contains(userStars, repoMeta.Name)

		matchedTags := make(map[string]metaTypes.Descriptor)
		for tag, descriptor := range repoMeta.Tags {
			matchedTags[tag] = descriptor

			switch descriptor.MediaType {
			case ispec.MediaTypeImageManifest:
				manifestDigest := descriptor.Digest

				manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifestDigest, //nolint:contextcheck
					manifestMetadataMap)
				if err != nil {
					return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
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
					return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
						pageInfo,
						fmt.Errorf("repodb: error while getting index data for digest %s %w", indexDigest, err)
				}

				var indexContent ispec.Index

				err = json.Unmarshal(indexData.IndexBlob, &indexContent)
				if err != nil {
					return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
						pageInfo,
						fmt.Errorf("repodb: error while unmashaling index content for digest %s %w", indexDigest, err)
				}

				manifestHasBeenMatched := false

				for _, manifest := range indexContent.Manifests {
					manifestDigest := manifest.Digest.String()

					manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifestDigest, //nolint:contextcheck
						manifestMetadataMap)
					if err != nil {
						return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
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
				dwr.Log.Error().Str("mediaType", descriptor.MediaType).Msg("Unsupported media type")

				continue
			}
		}

		if len(matchedTags) == 0 {
			continue
		}

		repoMeta.Tags = matchedTags

		pageFinder.Add(metaTypes.DetailedRepoMeta{
			RepoMetadata: repoMeta,
		})
	}

	foundRepos, pageInfo := pageFinder.Page()

	foundManifestMetadataMap, foundindexDataMap, err := common.FilterDataByRepo(foundRepos, manifestMetadataMap,
		indexDataMap)

	return foundRepos, foundManifestMetadataMap, foundindexDataMap, pageInfo, err
}

func (dwr *DBWrapper) FilterRepos(ctx context.Context, filter metaTypes.FilterRepoFunc,
	requestedPage metaTypes.PageInput,
) (
	[]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData, zcommon.PageInfo,
	error,
) {
	var (
		repoMetaAttributeIterator AttributesIterator
		pageInfo                  zcommon.PageInfo
		userBookmarks             = getUserBookmarks(ctx, dwr)
		userStars                 = getUserStars(ctx, dwr)
	)

	repoMetaAttributeIterator = NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	pageFinder, err := pagination.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
			pageInfo, err
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)
	if err != nil {
		return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
			pageInfo, err
	}

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
				pageInfo, err
		}

		var repoMeta metaTypes.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
				pageInfo, err
		}

		if ok, err := localCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repoMeta.Name)
		repoMeta.IsStarred = zcommon.Contains(userStars, repoMeta.Name)

		if filter(repoMeta) {
			pageFinder.Add(metaTypes.DetailedRepoMeta{
				RepoMetadata: repoMeta,
			})
		}
	}

	foundRepos, pageInfo := pageFinder.Page()

	foundManifestMetadataMap, foundIndexDataMap, err := common.FetchDataForRepos(dwr, foundRepos)

	return foundRepos, foundManifestMetadataMap, foundIndexDataMap, pageInfo, err
}

func (dwr *DBWrapper) SearchTags(ctx context.Context, searchText string, filter metaTypes.Filter,
	requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData, zcommon.PageInfo,
	error,
) {
	var (
		manifestMetadataMap       = make(map[string]metaTypes.ManifestMetadata)
		indexDataMap              = make(map[string]metaTypes.IndexData)
		repoMetaAttributeIterator AttributesIterator
		pageFinder                pagination.PageFinder
		pageInfo                  zcommon.PageInfo
		userBookmarks             = getUserBookmarks(ctx, dwr)
		userStars                 = getUserStars(ctx, dwr)
	)

	pageFinder, err := pagination.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
			pageInfo, err
	}

	repoMetaAttributeIterator = NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	searchedRepo, searchedTag, err := common.GetRepoTag(searchText)
	if err != nil {
		return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
			pageInfo,
			fmt.Errorf("repodb: error while parsing search text, invalid format %w", err)
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			// log
			return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
				pageInfo, err
		}

		var repoMeta metaTypes.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
				pageInfo, err
		}

		if ok, err := localCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		if repoMeta.Name != searchedRepo {
			continue
		}

		repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repoMeta.Name)
		repoMeta.IsStarred = zcommon.Contains(userStars, repoMeta.Name)

		matchedTags := make(map[string]metaTypes.Descriptor)

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
					return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
						pageInfo,
						fmt.Errorf("repodb: error while unmashaling manifest metadata for digest %s %w", descriptor.Digest, err)
				}

				imageFilterData, err := collectImageManifestFilterData(manifestDigest, repoMeta, manifestMeta)
				if err != nil {
					return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
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
					return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
						pageInfo,
						fmt.Errorf("%w", err)
				}

				var indexContent ispec.Index

				err = json.Unmarshal(indexData.IndexBlob, &indexContent)
				if err != nil {
					return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
						pageInfo,
						fmt.Errorf("repodb: error while unmashaling index content for digest %s %w", indexDigest, err)
				}

				manifestHasBeenMatched := false

				for _, manifest := range indexContent.Manifests {
					manifestDigest := manifest.Digest.String()

					manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifestDigest, //nolint:contextcheck
						manifestMetadataMap)
					if err != nil {
						return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
							pageInfo,
							fmt.Errorf("%w", err)
					}

					manifestFilterData, err := collectImageManifestFilterData(manifestDigest, repoMeta, manifestMeta)
					if err != nil {
						return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
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
				dwr.Log.Error().Str("mediaType", descriptor.MediaType).Msg("Unsupported media type")

				continue
			}
		}

		if len(matchedTags) == 0 {
			continue
		}

		repoMeta.Tags = matchedTags

		pageFinder.Add(metaTypes.DetailedRepoMeta{
			RepoMetadata: repoMeta,
		})
	}

	foundRepos, pageInfo := pageFinder.Page()

	foundManifestMetadataMap, foundindexDataMap, err := common.FilterDataByRepo(foundRepos, manifestMetadataMap,
		indexDataMap)

	return foundRepos, foundManifestMetadataMap, foundindexDataMap, pageInfo, err
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

func (dwr *DBWrapper) SetRepoMeta(repo string, repoMeta metaTypes.RepoMetadata) error {
	repoMeta.Name = repo

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

func (dwr *DBWrapper) ToggleBookmarkRepo(ctx context.Context, repo string) (
	metaTypes.ToggleState, error,
) {
	res := metaTypes.NotChanged

	if ok, err := localCtx.RepoIsUserAvailable(ctx, repo); !ok || err != nil {
		return res, zerr.ErrUserDataNotAllowed
	}

	userMeta, err := dwr.GetUserMeta(ctx)
	if err != nil {
		if errors.Is(err, zerr.ErrUserDataNotFound) {
			return metaTypes.NotChanged, nil
		}

		return res, err
	}

	if !zcommon.Contains(userMeta.BookmarkedRepos, repo) {
		userMeta.BookmarkedRepos = append(userMeta.BookmarkedRepos, repo)
		res = metaTypes.Added
	} else {
		userMeta.BookmarkedRepos = zcommon.RemoveFrom(userMeta.BookmarkedRepos, repo)
		res = metaTypes.Removed
	}

	if res != metaTypes.NotChanged {
		err = dwr.SetUserMeta(ctx, userMeta)
	}

	if err != nil {
		res = metaTypes.NotChanged

		return res, err
	}

	return res, nil
}

func (dwr *DBWrapper) GetBookmarkedRepos(ctx context.Context) ([]string, error) {
	userMeta, err := dwr.GetUserMeta(ctx)

	if errors.Is(err, zerr.ErrUserDataNotFound) {
		return []string{}, nil
	}

	return userMeta.BookmarkedRepos, err
}

func (dwr *DBWrapper) ToggleStarRepo(ctx context.Context, repo string) (
	metaTypes.ToggleState, error,
) {
	res := metaTypes.NotChanged

	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return res, err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)

	if userid == "" {
		// empty user is anonymous, it has no data
		return res, zerr.ErrUserDataNotAllowed
	}

	if ok, err := localCtx.RepoIsUserAvailable(ctx, repo); !ok || err != nil {
		return res, zerr.ErrUserDataNotAllowed
	}

	userData, err := dwr.GetUserMeta(ctx)
	if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
		return res, err
	}

	if !zcommon.Contains(userData.StarredRepos, repo) {
		userData.StarredRepos = append(userData.StarredRepos, repo)
		res = metaTypes.Added
	} else {
		userData.StarredRepos = zcommon.RemoveFrom(userData.StarredRepos, repo)
		res = metaTypes.Removed
	}

	if res != metaTypes.NotChanged {
		repoMeta, err := dwr.GetRepoMeta(repo) //nolint:contextcheck
		if err != nil {
			return metaTypes.NotChanged, err
		}

		switch res {
		case metaTypes.Added:
			repoMeta.Stars++
		case metaTypes.Removed:
			repoMeta.Stars--
		}

		repoAttributeValue, err := attributevalue.Marshal(repoMeta)
		if err != nil {
			return metaTypes.NotChanged, err
		}

		userAttributeValue, err := attributevalue.Marshal(userData)
		if err != nil {
			return metaTypes.NotChanged, err
		}

		_, err = dwr.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
			TransactItems: []types.TransactWriteItem{
				{
					// Update User Meta
					Update: &types.Update{
						ExpressionAttributeNames: map[string]string{
							"#UM": "UserData",
						},
						ExpressionAttributeValues: map[string]types.AttributeValue{
							":UserData": userAttributeValue,
						},
						Key: map[string]types.AttributeValue{
							"UserID": &types.AttributeValueMemberS{
								Value: userid,
							},
						},
						TableName:        aws.String(dwr.UserDataTablename),
						UpdateExpression: aws.String("SET #UM = :UserData"),
					},
				},
				{
					// Update Repo Meta with updated repo stars
					Update: &types.Update{
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
					},
				},
			},
		})
		if err != nil {
			return metaTypes.NotChanged, err
		}
	}

	return res, nil
}

func (dwr *DBWrapper) GetStarredRepos(ctx context.Context) ([]string, error) {
	userMeta, err := dwr.GetUserMeta(ctx)

	if errors.Is(err, zerr.ErrUserDataNotFound) {
		return []string{}, nil
	}

	return userMeta.StarredRepos, err
}

func (dwr *DBWrapper) GetUserMeta(ctx context.Context) (metaTypes.UserData, error) {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return metaTypes.UserData{}, err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)

	if userid == "" {
		// empty user is anonymous, it has no data
		return metaTypes.UserData{}, nil
	}

	resp, err := dwr.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(dwr.UserDataTablename),
		Key: map[string]types.AttributeValue{
			"UserID": &types.AttributeValueMemberS{Value: userid},
		},
	})
	if err != nil {
		return metaTypes.UserData{}, err
	}

	if resp.Item == nil {
		return metaTypes.UserData{}, zerr.ErrUserDataNotFound
	}

	var userMeta metaTypes.UserData

	err = attributevalue.Unmarshal(resp.Item["UserData"], &userMeta)
	if err != nil {
		return metaTypes.UserData{}, err
	}

	return userMeta, nil
}

func (dwr *DBWrapper) createUserDataTable() error {
	_, err := dwr.Client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String(dwr.UserDataTablename),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("UserID"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("UserID"),
				KeyType:       types.KeyTypeHash,
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})

	if err != nil && !strings.Contains(err.Error(), "Table already exists") {
		return err
	}

	return dwr.waitTableToBeCreated(dwr.UserDataTablename)
}

func (dwr *DBWrapper) SetUserMeta(ctx context.Context, userMeta metaTypes.UserData) error {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)

	if userid == "" {
		// empty user is anonymous, it has no data
		return zerr.ErrUserDataNotAllowed
	}

	userAttributeValue, err := attributevalue.Marshal(userMeta)
	if err != nil {
		return err
	}

	_, err = dwr.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#UM": "UserData",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":UserData": userAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"UserID": &types.AttributeValueMemberS{
				Value: userid,
			},
		},
		TableName:        aws.String(dwr.UserDataTablename),
		UpdateExpression: aws.String("SET #UM = :UserData"),
	})

	return err
}
