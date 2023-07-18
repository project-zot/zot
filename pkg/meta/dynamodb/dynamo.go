package dynamodb

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
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/meta/version"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
)

var errMetaDB = errors.New("metadb: error while constructing manifest meta")

type DynamoDB struct {
	Client                *dynamodb.Client
	APIKeyTablename       string
	RepoMetaTablename     string
	IndexDataTablename    string
	ManifestDataTablename string
	UserDataTablename     string
	VersionTablename      string
	Patches               []func(client *dynamodb.Client, tableNames map[string]string) error
	Log                   log.Logger
}

func New(client *dynamodb.Client, params DBDriverParameters, log log.Logger) (*DynamoDB, error) {
	dynamoWrapper := DynamoDB{
		Client:                client,
		RepoMetaTablename:     params.RepoMetaTablename,
		ManifestDataTablename: params.ManifestDataTablename,
		IndexDataTablename:    params.IndexDataTablename,
		VersionTablename:      params.VersionTablename,
		UserDataTablename:     params.UserDataTablename,
		APIKeyTablename:       params.APIKeyTablename,
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

	err = dynamoWrapper.createAPIKeyTable()
	if err != nil {
		return nil, err
	}

	// Using the Config value, create the DynamoDB client
	return &dynamoWrapper, nil
}

func (dwr *DynamoDB) SetManifestData(manifestDigest godigest.Digest, manifestData mTypes.ManifestData) error {
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

func (dwr *DynamoDB) GetManifestData(manifestDigest godigest.Digest) (mTypes.ManifestData, error) {
	resp, err := dwr.Client.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.ManifestDataTablename),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: manifestDigest.String()},
		},
	})
	if err != nil {
		return mTypes.ManifestData{}, err
	}

	if resp.Item == nil {
		return mTypes.ManifestData{}, zerr.ErrManifestDataNotFound
	}

	var manifestData mTypes.ManifestData

	err = attributevalue.Unmarshal(resp.Item["ManifestData"], &manifestData)
	if err != nil {
		return mTypes.ManifestData{}, err
	}

	return manifestData, nil
}

func (dwr *DynamoDB) SetManifestMeta(repo string, manifestDigest godigest.Digest, manifestMeta mTypes.ManifestMetadata,
) error {
	if manifestMeta.Signatures == nil {
		manifestMeta.Signatures = mTypes.ManifestSignatures{}
	}

	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		if !errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return err
		}

		repoMeta = mTypes.RepoMetadata{
			Name:       repo,
			Tags:       map[string]mTypes.Descriptor{},
			Statistics: map[string]mTypes.DescriptorStatistics{},
			Signatures: map[string]mTypes.ManifestSignatures{},
			Referrers:  map[string][]mTypes.ReferrerInfo{},
		}
	}

	err = dwr.SetManifestData(manifestDigest, mTypes.ManifestData{
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

func (dwr *DynamoDB) GetManifestMeta(repo string, manifestDigest godigest.Digest,
) (mTypes.ManifestMetadata, error) { //nolint:contextcheck
	manifestData, err := dwr.GetManifestData(manifestDigest)
	if err != nil {
		if errors.Is(err, zerr.ErrManifestDataNotFound) {
			return mTypes.ManifestMetadata{}, zerr.ErrManifestMetaNotFound
		}

		return mTypes.ManifestMetadata{},
			fmt.Errorf("%w for manifest '%s' from repo '%s'", errMetaDB, manifestDigest, repo)
	}

	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return mTypes.ManifestMetadata{}, zerr.ErrManifestMetaNotFound
		}

		return mTypes.ManifestMetadata{},
			fmt.Errorf("%w for manifest '%s' from repo '%s'", errMetaDB, manifestDigest, repo)
	}

	manifestMetadata := mTypes.ManifestMetadata{}

	manifestMetadata.ManifestBlob = manifestData.ManifestBlob
	manifestMetadata.ConfigBlob = manifestData.ConfigBlob
	manifestMetadata.DownloadCount = repoMeta.Statistics[manifestDigest.String()].DownloadCount

	manifestMetadata.Signatures = mTypes.ManifestSignatures{}

	if repoMeta.Signatures[manifestDigest.String()] != nil {
		manifestMetadata.Signatures = repoMeta.Signatures[manifestDigest.String()]
	}

	return manifestMetadata, nil
}

func (dwr *DynamoDB) IncrementRepoStars(repo string) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	repoMeta.Stars++

	err = dwr.SetRepoMeta(repo, repoMeta)

	return err
}

func (dwr *DynamoDB) DecrementRepoStars(repo string) error {
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

func (dwr *DynamoDB) GetRepoStars(repo string) (int, error) {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return 0, err
	}

	return repoMeta.Stars, nil
}

func (dwr *DynamoDB) SetIndexData(indexDigest godigest.Digest, indexData mTypes.IndexData) error {
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

func (dwr *DynamoDB) GetIndexData(indexDigest godigest.Digest) (mTypes.IndexData, error) {
	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.IndexDataTablename),
		Key: map[string]types.AttributeValue{
			"IndexDigest": &types.AttributeValueMemberS{
				Value: indexDigest.String(),
			},
		},
	})
	if err != nil {
		return mTypes.IndexData{}, err
	}

	if resp.Item == nil {
		return mTypes.IndexData{}, zerr.ErrRepoMetaNotFound
	}

	var indexData mTypes.IndexData

	err = attributevalue.Unmarshal(resp.Item["IndexData"], &indexData)
	if err != nil {
		return mTypes.IndexData{}, err
	}

	return indexData, nil
}

func (dwr DynamoDB) SetReferrer(repo string, referredDigest godigest.Digest, referrer mTypes.ReferrerInfo) error {
	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.RepoMetaTablename),
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return err
	}

	repoMeta := mTypes.RepoMetadata{
		Name:       repo,
		Tags:       map[string]mTypes.Descriptor{},
		Statistics: map[string]mTypes.DescriptorStatistics{},
		Signatures: map[string]mTypes.ManifestSignatures{},
		Referrers:  map[string][]mTypes.ReferrerInfo{},
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

func (dwr DynamoDB) GetReferrers(repo string, referredDigest godigest.Digest) ([]mTypes.ReferrerInfo, error) {
	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.RepoMetaTablename),
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return []mTypes.ReferrerInfo{}, err
	}

	repoMeta := mTypes.RepoMetadata{
		Name:       repo,
		Tags:       map[string]mTypes.Descriptor{},
		Statistics: map[string]mTypes.DescriptorStatistics{},
		Signatures: map[string]mTypes.ManifestSignatures{},
		Referrers:  map[string][]mTypes.ReferrerInfo{},
	}

	if resp.Item != nil {
		err := attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
		if err != nil {
			return []mTypes.ReferrerInfo{}, err
		}
	}

	return repoMeta.Referrers[referredDigest.String()], nil
}

func (dwr DynamoDB) DeleteReferrer(repo string, referredDigest godigest.Digest,
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

	repoMeta := mTypes.RepoMetadata{
		Name:       repo,
		Tags:       map[string]mTypes.Descriptor{},
		Statistics: map[string]mTypes.DescriptorStatistics{},
		Signatures: map[string]mTypes.ManifestSignatures{},
		Referrers:  map[string][]mTypes.ReferrerInfo{},
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

func (dwr DynamoDB) GetReferrersInfo(repo string, referredDigest godigest.Digest,
	artifactTypes []string,
) ([]mTypes.ReferrerInfo, error) {
	referrersInfo, err := dwr.GetReferrers(repo, referredDigest)
	if err != nil {
		return nil, err
	}

	filteredResults := make([]mTypes.ReferrerInfo, 0, len(referrersInfo))

	for _, referrerInfo := range referrersInfo {
		if !common.MatchesArtifactTypes(referrerInfo.ArtifactType, artifactTypes) {
			continue
		}

		filteredResults = append(filteredResults, referrerInfo)
	}

	return filteredResults, nil
}

func (dwr *DynamoDB) SetRepoReference(repo string, reference string, manifestDigest godigest.Digest,
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

	repoMeta := mTypes.RepoMetadata{
		Name:       repo,
		Tags:       map[string]mTypes.Descriptor{},
		Statistics: map[string]mTypes.DescriptorStatistics{},
		Signatures: map[string]mTypes.ManifestSignatures{},
		Referrers:  map[string][]mTypes.ReferrerInfo{},
	}

	if resp.Item != nil {
		err := attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
		if err != nil {
			return err
		}
	}

	if !common.ReferenceIsDigest(reference) {
		repoMeta.Tags[reference] = mTypes.Descriptor{
			Digest:    manifestDigest.String(),
			MediaType: mediaType,
		}
	}

	if _, ok := repoMeta.Statistics[manifestDigest.String()]; !ok {
		repoMeta.Statistics[manifestDigest.String()] = mTypes.DescriptorStatistics{DownloadCount: 0}
	}

	if _, ok := repoMeta.Signatures[manifestDigest.String()]; !ok {
		repoMeta.Signatures[manifestDigest.String()] = mTypes.ManifestSignatures{}
	}

	if _, ok := repoMeta.Referrers[manifestDigest.String()]; !ok {
		repoMeta.Referrers[manifestDigest.String()] = []mTypes.ReferrerInfo{}
	}

	err = dwr.SetRepoMeta(repo, repoMeta)

	return err
}

func (dwr *DynamoDB) DeleteRepoTag(repo string, tag string) error {
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

	var repoMeta mTypes.RepoMetadata

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

func (dwr *DynamoDB) GetRepoMeta(repo string) (mTypes.RepoMetadata, error) {
	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.RepoMetaTablename),
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return mTypes.RepoMetadata{}, err
	}

	if resp.Item == nil {
		return mTypes.RepoMetadata{}, zerr.ErrRepoMetaNotFound
	}

	var repoMeta mTypes.RepoMetadata

	err = attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
	if err != nil {
		return mTypes.RepoMetadata{}, err
	}

	return repoMeta, nil
}

func (dwr *DynamoDB) GetUserRepoMeta(ctx context.Context, repo string) (mTypes.RepoMetadata, error) {
	resp, err := dwr.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(dwr.RepoMetaTablename),
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return mTypes.RepoMetadata{}, err
	}

	if resp.Item == nil {
		return mTypes.RepoMetadata{}, zerr.ErrRepoMetaNotFound
	}

	var repoMeta mTypes.RepoMetadata

	err = attributevalue.Unmarshal(resp.Item["RepoMetadata"], &repoMeta)
	if err != nil {
		return mTypes.RepoMetadata{}, err
	}

	userData, err := dwr.GetUserData(ctx)
	if err != nil {
		return mTypes.RepoMetadata{}, err
	}

	repoMeta.IsBookmarked = zcommon.Contains(userData.BookmarkedRepos, repo)
	repoMeta.IsStarred = zcommon.Contains(userData.StarredRepos, repo)

	return repoMeta, nil
}

func (dwr *DynamoDB) IncrementImageDownloads(repo string, reference string) error {
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

func (dwr *DynamoDB) UpdateSignaturesValidity(repo string, manifestDigest godigest.Digest) error {
	// get ManifestData of signed manifest
	var blob []byte

	manifestData, err := dwr.GetManifestData(manifestDigest)
	if err != nil {
		if errors.Is(err, zerr.ErrManifestDataNotFound) {
			indexData, err := dwr.GetIndexData(manifestDigest)
			if err != nil {
				return nil //nolint: nilerr
			}

			blob = indexData.IndexBlob
		} else {
			return fmt.Errorf("%w for manifest '%s' from repo '%s'", errMetaDB, manifestDigest, repo)
		}
	} else {
		blob = manifestData.ManifestBlob
	}

	// update signatures with details about validity and author
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	manifestSignatures := mTypes.ManifestSignatures{}

	for sigType, sigs := range repoMeta.Signatures[manifestDigest.String()] {
		signaturesInfo := []mTypes.SignatureInfo{}

		for _, sigInfo := range sigs {
			layersInfo := []mTypes.LayerInfo{}

			for _, layerInfo := range sigInfo.LayersInfo {
				author, date, isTrusted, _ := signatures.VerifySignature(sigType, layerInfo.LayerContent, layerInfo.SignatureKey,
					manifestDigest, blob, repo)

				if isTrusted {
					layerInfo.Signer = author
				}

				if !date.IsZero() {
					layerInfo.Signer = author
					layerInfo.Date = date
				}

				layersInfo = append(layersInfo, layerInfo)
			}

			signaturesInfo = append(signaturesInfo, mTypes.SignatureInfo{
				SignatureManifestDigest: sigInfo.SignatureManifestDigest,
				LayersInfo:              layersInfo,
			})
		}

		manifestSignatures[sigType] = signaturesInfo
	}

	repoMeta.Signatures[manifestDigest.String()] = manifestSignatures

	return dwr.SetRepoMeta(repoMeta.Name, repoMeta)
}

func (dwr *DynamoDB) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
	sygMeta mTypes.SignatureMetadata,
) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			repoMeta = mTypes.RepoMetadata{
				Name:       repo,
				Tags:       map[string]mTypes.Descriptor{},
				Statistics: map[string]mTypes.DescriptorStatistics{},
				Signatures: map[string]mTypes.ManifestSignatures{
					signedManifestDigest.String(): {
						sygMeta.SignatureType: []mTypes.SignatureInfo{
							{
								SignatureManifestDigest: sygMeta.SignatureDigest,
								LayersInfo:              sygMeta.LayersInfo,
							},
						},
					},
				},
				Referrers: map[string][]mTypes.ReferrerInfo{},
			}

			return dwr.SetRepoMeta(repo, repoMeta)
		}

		return err
	}

	var (
		manifestSignatures mTypes.ManifestSignatures
		found              bool
	)

	if manifestSignatures, found = repoMeta.Signatures[signedManifestDigest.String()]; !found {
		manifestSignatures = mTypes.ManifestSignatures{}
	}

	signatureSlice := manifestSignatures[sygMeta.SignatureType]
	if !common.SignatureAlreadyExists(signatureSlice, sygMeta) {
		if sygMeta.SignatureType == signatures.NotationSignature {
			signatureSlice = append(signatureSlice, mTypes.SignatureInfo{
				SignatureManifestDigest: sygMeta.SignatureDigest,
				LayersInfo:              sygMeta.LayersInfo,
			})
		} else if sygMeta.SignatureType == signatures.CosignSignature {
			signatureSlice = []mTypes.SignatureInfo{{
				SignatureManifestDigest: sygMeta.SignatureDigest,
				LayersInfo:              sygMeta.LayersInfo,
			}}
		}
	}

	manifestSignatures[sygMeta.SignatureType] = signatureSlice

	repoMeta.Signatures[signedManifestDigest.String()] = manifestSignatures

	return dwr.SetRepoMeta(repoMeta.Name, repoMeta)
}

func (dwr *DynamoDB) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
	sigMeta mTypes.SignatureMetadata,
) error {
	repoMeta, err := dwr.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	sigType := sigMeta.SignatureType

	var (
		manifestSignatures mTypes.ManifestSignatures
		found              bool
	)

	if manifestSignatures, found = repoMeta.Signatures[signedManifestDigest.String()]; !found {
		return zerr.ErrManifestMetaNotFound
	}

	signatureSlice := manifestSignatures[sigType]

	newSignatureSlice := make([]mTypes.SignatureInfo, 0, len(signatureSlice)-1)

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

func (dwr *DynamoDB) GetMultipleRepoMeta(ctx context.Context,
	filter func(repoMeta mTypes.RepoMetadata) bool, requestedPage mTypes.PageInput,
) ([]mTypes.RepoMetadata, error) {
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
			return []mTypes.RepoMetadata{}, err
		}

		var repoMeta mTypes.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []mTypes.RepoMetadata{}, err
		}

		if ok, err := localCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		if filter(repoMeta) {
			pageFinder.Add(mTypes.DetailedRepoMeta{
				RepoMetadata: repoMeta,
			})
		}
	}

	foundRepos, _ := pageFinder.Page()

	return foundRepos, err
}

func (dwr *DynamoDB) SearchRepos(ctx context.Context, searchText string, filter mTypes.Filter,
	requestedPage mTypes.PageInput,
) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, zcommon.PageInfo, error) {
	var (
		manifestMetadataMap       = make(map[string]mTypes.ManifestMetadata)
		indexDataMap              = make(map[string]mTypes.IndexData)
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
		return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
			pageInfo, err
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
				pageInfo, err
		}

		var repoMeta mTypes.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
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
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
						pageInfo,
						fmt.Errorf("%w", err)
				}

				manifestFilterData, err := collectImageManifestFilterData(manifestDigest, repoMeta, manifestMeta)
				if err != nil {
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
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
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
						pageInfo,
						fmt.Errorf("%w", err)
				}

				// this also updates manifestMetadataMap
				indexFilterData, err := dwr.collectImageIndexFilterInfo(indexDigest, repoMeta, indexData, //nolint:contextcheck
					manifestMetadataMap)
				if err != nil {
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
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

		repoFilterData := mTypes.FilterData{
			OsList:        common.GetMapKeys(osSet),
			ArchList:      common.GetMapKeys(archSet),
			LastUpdated:   repoLastUpdated,
			DownloadCount: repoDownloads,
			IsSigned:      isSigned,
		}

		if !common.AcceptedByFilter(filter, repoFilterData) {
			continue
		}

		pageFinder.Add(mTypes.DetailedRepoMeta{
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

func getUserStars(ctx context.Context, dwr *DynamoDB) []string {
	starredRepos, err := dwr.GetStarredRepos(ctx)
	if err != nil {
		return []string{}
	}

	return starredRepos
}

func getUserBookmarks(ctx context.Context, dwr *DynamoDB) []string {
	bookmarkedRepos, err := dwr.GetBookmarkedRepos(ctx)
	if err != nil {
		return []string{}
	}

	return bookmarkedRepos
}

func (dwr *DynamoDB) fetchManifestMetaWithCheck(repoName string, manifestDigest string,
	manifestMetadataMap map[string]mTypes.ManifestMetadata,
) (mTypes.ManifestMetadata, error) {
	var (
		manifestMeta mTypes.ManifestMetadata
		err          error
	)

	manifestMeta, manifestDownloaded := manifestMetadataMap[manifestDigest]

	if !manifestDownloaded {
		manifestMeta, err = dwr.GetManifestMeta(repoName, godigest.Digest(manifestDigest)) //nolint:contextcheck
		if err != nil {
			return mTypes.ManifestMetadata{}, err
		}
	}

	return manifestMeta, nil
}

func collectImageManifestFilterData(digest string, repoMeta mTypes.RepoMetadata,
	manifestMeta mTypes.ManifestMetadata,
) (mTypes.FilterData, error) {
	// get fields related to filtering
	var (
		configContent ispec.Image
		osList        []string
		archList      []string
	)

	err := json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
	if err != nil {
		return mTypes.FilterData{}, fmt.Errorf("metadb: error while unmarshaling config content %w", err)
	}

	if configContent.OS != "" {
		osList = append(osList, configContent.OS)
	}

	if configContent.Architecture != "" {
		archList = append(archList, configContent.Architecture)
	}

	return mTypes.FilterData{
		DownloadCount: repoMeta.Statistics[digest].DownloadCount,
		OsList:        osList,
		ArchList:      archList,
		LastUpdated:   common.GetImageLastUpdatedTimestamp(configContent),
		IsSigned:      common.CheckIsSigned(repoMeta.Signatures[digest]),
	}, nil
}

func (dwr *DynamoDB) fetchIndexDataWithCheck(indexDigest string, indexDataMap map[string]mTypes.IndexData,
) (mTypes.IndexData, error) {
	var (
		indexData mTypes.IndexData
		err       error
	)

	indexData, indexExists := indexDataMap[indexDigest]

	if !indexExists {
		indexData, err = dwr.GetIndexData(godigest.Digest(indexDigest)) //nolint:contextcheck
		if err != nil {
			return mTypes.IndexData{},
				fmt.Errorf("metadb: error while unmarshaling index data for digest %s \n%w", indexDigest, err)
		}
	}

	return indexData, err
}

func (dwr *DynamoDB) collectImageIndexFilterInfo(indexDigest string, repoMeta mTypes.RepoMetadata,
	indexData mTypes.IndexData, manifestMetadataMap map[string]mTypes.ManifestMetadata,
) (mTypes.FilterData, error) {
	var indexContent ispec.Index

	err := json.Unmarshal(indexData.IndexBlob, &indexContent)
	if err != nil {
		return mTypes.FilterData{},
			fmt.Errorf("metadb: error while unmarshaling index content for digest %s %w", indexDigest, err)
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
			return mTypes.FilterData{},
				fmt.Errorf("%w", err)
		}

		manifestFilterData, err := collectImageManifestFilterData(manifestDigest.String(), repoMeta,
			manifestMeta)
		if err != nil {
			return mTypes.FilterData{},
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

	return mTypes.FilterData{
		DownloadCount: repoMeta.Statistics[indexDigest].DownloadCount,
		LastUpdated:   indexLastUpdated,
		OsList:        indexOsList,
		ArchList:      indexArchList,
		IsSigned:      common.CheckIsSigned(repoMeta.Signatures[indexDigest]),
	}, nil
}

func (dwr *DynamoDB) FilterTags(ctx context.Context, filterFunc mTypes.FilterFunc, filter mTypes.Filter,
	requestedPage mTypes.PageInput,
) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
	zcommon.PageInfo, error,
) {
	var (
		manifestMetadataMap       = make(map[string]mTypes.ManifestMetadata)
		indexDataMap              = make(map[string]mTypes.IndexData)
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
		return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
			pageInfo, err
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
				pageInfo, err
		}

		var repoMeta mTypes.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
				pageInfo, err
		}

		if ok, err := localCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repoMeta.Name)
		repoMeta.IsStarred = zcommon.Contains(userStars, repoMeta.Name)

		matchedTags := make(map[string]mTypes.Descriptor)

		for tag, descriptor := range repoMeta.Tags {
			switch descriptor.MediaType {
			case ispec.MediaTypeImageManifest:
				manifestDigest := descriptor.Digest

				manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifestDigest, //nolint:contextcheck
					manifestMetadataMap)
				if err != nil {
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
						pageInfo,
						fmt.Errorf("metadb: error while unmashaling manifest metadata for digest %s \n%w", manifestDigest, err)
				}

				imageFilterData, err := collectImageManifestFilterData(manifestDigest, repoMeta, manifestMeta)
				if err != nil {
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
						pageInfo,
						fmt.Errorf("metadb: error collecting filter data for manifest with digest %s %w", manifestDigest, err)
				}

				if !common.AcceptedByFilter(filter, imageFilterData) {
					delete(matchedTags, tag)

					continue
				}

				if filterFunc(repoMeta, manifestMeta) {
					matchedTags[tag] = descriptor
					manifestMetadataMap[manifestDigest] = manifestMeta
				}
			case ispec.MediaTypeImageIndex:
				indexDigest := descriptor.Digest

				indexData, err := dwr.fetchIndexDataWithCheck(indexDigest, indexDataMap) //nolint:contextcheck
				if err != nil {
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
						pageInfo,
						fmt.Errorf("metadb: error while getting index data for digest %s %w", indexDigest, err)
				}

				var indexContent ispec.Index

				err = json.Unmarshal(indexData.IndexBlob, &indexContent)
				if err != nil {
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
						pageInfo,
						fmt.Errorf("metadb: error while unmashaling index content for digest %s %w", indexDigest, err)
				}

				matchedManifests := []ispec.Descriptor{}

				for _, manifest := range indexContent.Manifests {
					manifestDigest := manifest.Digest.String()

					manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifestDigest, //nolint:contextcheck
						manifestMetadataMap)
					if err != nil {
						return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
							pageInfo,
							fmt.Errorf("%w metadb: error while getting manifest data for digest %s", err, manifestDigest)
					}

					manifestFilterData, err := collectImageManifestFilterData(manifestDigest, repoMeta, manifestMeta)
					if err != nil {
						return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
							pageInfo,
							fmt.Errorf("metadb: error collecting filter data for manifest with digest %s %w", manifestDigest, err)
					}

					if !common.AcceptedByFilter(filter, manifestFilterData) {
						continue
					}

					if filterFunc(repoMeta, manifestMeta) {
						matchedManifests = append(matchedManifests, manifest)
						manifestMetadataMap[manifestDigest] = manifestMeta
					}
				}

				if len(matchedManifests) > 0 {
					indexContent.Manifests = matchedManifests

					indexBlob, err := json.Marshal(indexContent)
					if err != nil {
						return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
							pageInfo, err
					}

					indexData.IndexBlob = indexBlob

					indexDataMap[indexDigest] = indexData
					matchedTags[tag] = descriptor
				}
			default:
				dwr.Log.Error().Str("mediaType", descriptor.MediaType).Msg("Unsupported media type")

				continue
			}
		}

		if len(matchedTags) == 0 {
			continue
		}

		repoMeta.Tags = matchedTags

		pageFinder.Add(mTypes.DetailedRepoMeta{
			RepoMetadata: repoMeta,
		})
	}

	foundRepos, pageInfo := pageFinder.Page()

	foundManifestMetadataMap, foundindexDataMap, err := common.FilterDataByRepo(foundRepos, manifestMetadataMap,
		indexDataMap)

	return foundRepos, foundManifestMetadataMap, foundindexDataMap, pageInfo, err
}

func (dwr *DynamoDB) FilterRepos(ctx context.Context,
	filter mTypes.FilterRepoFunc,
	requestedPage mTypes.PageInput,
) (
	[]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
	zcommon.PageInfo, error,
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
		return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
			pageInfo, err
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)
	if err != nil {
		return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
			pageInfo, err
	}

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
				pageInfo, err
		}

		var repoMeta mTypes.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
				pageInfo, err
		}

		if ok, err := localCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repoMeta.Name)
		repoMeta.IsStarred = zcommon.Contains(userStars, repoMeta.Name)

		if filter(repoMeta) {
			pageFinder.Add(mTypes.DetailedRepoMeta{
				RepoMetadata: repoMeta,
			})
		}
	}

	foundRepos, pageInfo := pageFinder.Page()

	foundManifestMetadataMap, foundIndexDataMap, err := common.FetchDataForRepos(dwr, foundRepos)

	return foundRepos, foundManifestMetadataMap, foundIndexDataMap, pageInfo, err
}

func (dwr *DynamoDB) SearchTags(ctx context.Context, searchText string, filter mTypes.Filter,
	requestedPage mTypes.PageInput,
) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
	zcommon.PageInfo, error,
) {
	var (
		manifestMetadataMap       = make(map[string]mTypes.ManifestMetadata)
		indexDataMap              = make(map[string]mTypes.IndexData)
		repoMetaAttributeIterator AttributesIterator
		pageFinder                pagination.PageFinder
		pageInfo                  zcommon.PageInfo
		userBookmarks             = getUserBookmarks(ctx, dwr)
		userStars                 = getUserStars(ctx, dwr)
	)

	pageFinder, err := pagination.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
			pageInfo, err
	}

	repoMetaAttributeIterator = NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	searchedRepo, searchedTag, err := common.GetRepoTag(searchText)
	if err != nil {
		return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
			pageInfo,
			fmt.Errorf("metadb: error while parsing search text, invalid format %w", err)
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			// log
			return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
				pageInfo, err
		}

		var repoMeta mTypes.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
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

		matchedTags := make(map[string]mTypes.Descriptor)

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
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
						pageInfo,
						fmt.Errorf("metadb: error while unmashaling manifest metadata for digest %s %w", descriptor.Digest, err)
				}

				imageFilterData, err := collectImageManifestFilterData(manifestDigest, repoMeta, manifestMeta)
				if err != nil {
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
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
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
						pageInfo,
						fmt.Errorf("%w", err)
				}

				var indexContent ispec.Index

				err = json.Unmarshal(indexData.IndexBlob, &indexContent)
				if err != nil {
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
						pageInfo,
						fmt.Errorf("metadb: error while unmashaling index content for digest %s %w", indexDigest, err)
				}

				manifestHasBeenMatched := false

				for _, manifest := range indexContent.Manifests {
					manifestDigest := manifest.Digest.String()

					manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifestDigest, //nolint:contextcheck
						manifestMetadataMap)
					if err != nil {
						return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
							pageInfo,
							fmt.Errorf("%w", err)
					}

					manifestFilterData, err := collectImageManifestFilterData(manifestDigest, repoMeta, manifestMeta)
					if err != nil {
						return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
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

		pageFinder.Add(mTypes.DetailedRepoMeta{
			RepoMetadata: repoMeta,
		})
	}

	foundRepos, pageInfo := pageFinder.Page()

	foundManifestMetadataMap, foundindexDataMap, err := common.FilterDataByRepo(foundRepos, manifestMetadataMap,
		indexDataMap)

	return foundRepos, foundManifestMetadataMap, foundindexDataMap, pageInfo, err
}

func (dwr *DynamoDB) PatchDB() error {
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

func (dwr *DynamoDB) SetRepoMeta(repo string, repoMeta mTypes.RepoMetadata) error {
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

func (dwr *DynamoDB) createRepoMetaTable() error {
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

func (dwr *DynamoDB) deleteRepoMetaTable() error {
	_, err := dwr.Client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
		TableName: aws.String(dwr.RepoMetaTablename),
	})

	if temp := new(types.ResourceNotFoundException); errors.As(err, &temp) {
		return nil
	}

	return dwr.waitTableToBeDeleted(dwr.RepoMetaTablename)
}

func (dwr *DynamoDB) ResetRepoMetaTable() error {
	err := dwr.deleteRepoMetaTable()
	if err != nil {
		return err
	}

	return dwr.createRepoMetaTable()
}

func (dwr *DynamoDB) waitTableToBeCreated(tableName string) error {
	const maxWaitTime = 20 * time.Second

	waiter := dynamodb.NewTableExistsWaiter(dwr.Client)

	return waiter.Wait(context.Background(), &dynamodb.DescribeTableInput{
		TableName: &tableName,
	}, maxWaitTime)
}

func (dwr *DynamoDB) waitTableToBeDeleted(tableName string) error {
	const maxWaitTime = 20 * time.Second

	waiter := dynamodb.NewTableNotExistsWaiter(dwr.Client)

	return waiter.Wait(context.Background(), &dynamodb.DescribeTableInput{
		TableName: &tableName,
	}, maxWaitTime)
}

func (dwr *DynamoDB) createManifestDataTable() error {
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

func (dwr *DynamoDB) createIndexDataTable() error {
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

func (dwr *DynamoDB) createVersionTable() error {
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

func (dwr *DynamoDB) getDBVersion() (string, error) {
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

func (dwr *DynamoDB) deleteManifestDataTable() error {
	_, err := dwr.Client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
		TableName: aws.String(dwr.ManifestDataTablename),
	})

	if temp := new(types.ResourceNotFoundException); errors.As(err, &temp) {
		return nil
	}

	return dwr.waitTableToBeDeleted(dwr.ManifestDataTablename)
}

func (dwr *DynamoDB) ResetManifestDataTable() error {
	err := dwr.deleteManifestDataTable()
	if err != nil {
		return err
	}

	return dwr.createManifestDataTable()
}

func (dwr *DynamoDB) ToggleBookmarkRepo(ctx context.Context, repo string) (
	mTypes.ToggleState, error,
) {
	res := mTypes.NotChanged

	if ok, err := localCtx.RepoIsUserAvailable(ctx, repo); !ok || err != nil {
		return res, zerr.ErrUserDataNotAllowed
	}

	userData, err := dwr.GetUserData(ctx)
	if err != nil {
		if errors.Is(err, zerr.ErrUserDataNotFound) {
			return mTypes.NotChanged, nil
		}

		return res, err
	}

	if !zcommon.Contains(userData.BookmarkedRepos, repo) {
		userData.BookmarkedRepos = append(userData.BookmarkedRepos, repo)
		res = mTypes.Added
	} else {
		userData.BookmarkedRepos = zcommon.RemoveFrom(userData.BookmarkedRepos, repo)
		res = mTypes.Removed
	}

	if res != mTypes.NotChanged {
		err = dwr.SetUserData(ctx, userData)
	}

	if err != nil {
		res = mTypes.NotChanged

		return res, err
	}

	return res, nil
}

func (dwr *DynamoDB) GetBookmarkedRepos(ctx context.Context) ([]string, error) {
	userMeta, err := dwr.GetUserData(ctx)

	if errors.Is(err, zerr.ErrUserDataNotFound) || errors.Is(err, zerr.ErrUserDataNotAllowed) {
		return []string{}, nil
	}

	return userMeta.BookmarkedRepos, err
}

func (dwr *DynamoDB) ToggleStarRepo(ctx context.Context, repo string) (
	mTypes.ToggleState, error,
) {
	res := mTypes.NotChanged

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

	userData, err := dwr.GetUserData(ctx)
	if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
		return res, err
	}

	if !zcommon.Contains(userData.StarredRepos, repo) {
		userData.StarredRepos = append(userData.StarredRepos, repo)
		res = mTypes.Added
	} else {
		userData.StarredRepos = zcommon.RemoveFrom(userData.StarredRepos, repo)
		res = mTypes.Removed
	}

	if res != mTypes.NotChanged {
		repoMeta, err := dwr.GetRepoMeta(repo) //nolint:contextcheck
		if err != nil {
			return mTypes.NotChanged, err
		}

		switch res {
		case mTypes.Added:
			repoMeta.Stars++
		case mTypes.Removed:
			repoMeta.Stars--
		}

		repoAttributeValue, err := attributevalue.Marshal(repoMeta)
		if err != nil {
			return mTypes.NotChanged, err
		}

		userAttributeValue, err := attributevalue.Marshal(userData)
		if err != nil {
			return mTypes.NotChanged, err
		}

		_, err = dwr.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
			TransactItems: []types.TransactWriteItem{
				{
					// Update User Profile
					Update: &types.Update{
						ExpressionAttributeNames: map[string]string{
							"#UP": "UserData",
						},
						ExpressionAttributeValues: map[string]types.AttributeValue{
							":UserData": userAttributeValue,
						},
						Key: map[string]types.AttributeValue{
							"Identity": &types.AttributeValueMemberS{
								Value: userid,
							},
						},
						TableName:        aws.String(dwr.UserDataTablename),
						UpdateExpression: aws.String("SET #UP = :UserData"),
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
			return mTypes.NotChanged, err
		}
	}

	return res, nil
}

func (dwr *DynamoDB) GetStarredRepos(ctx context.Context) ([]string, error) {
	userMeta, err := dwr.GetUserData(ctx)

	if errors.Is(err, zerr.ErrUserDataNotFound) || errors.Is(err, zerr.ErrUserDataNotAllowed) {
		return []string{}, nil
	}

	return userMeta.StarredRepos, err
}

func (dwr *DynamoDB) createUserDataTable() error {
	_, err := dwr.Client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String(dwr.UserDataTablename),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("Identity"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("Identity"),
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

func (dwr DynamoDB) createAPIKeyTable() error {
	_, err := dwr.Client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String(dwr.APIKeyTablename),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("HashedKey"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("HashedKey"),
				KeyType:       types.KeyTypeHash,
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})

	if err != nil && !strings.Contains(err.Error(), "Table already exists") {
		return err
	}

	return dwr.waitTableToBeCreated(dwr.APIKeyTablename)
}

func (dwr DynamoDB) SetUserGroups(ctx context.Context, groups []string) error {
	userData, err := dwr.GetUserData(ctx)
	if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
		return err
	}

	userData.Groups = append(userData.Groups, groups...)

	return dwr.SetUserData(ctx, userData)
}

func (dwr DynamoDB) GetUserGroups(ctx context.Context) ([]string, error) {
	userData, err := dwr.GetUserData(ctx)

	return userData.Groups, err
}

func (dwr DynamoDB) UpdateUserAPIKeyLastUsed(ctx context.Context, hashedKey string) error {
	userData, err := dwr.GetUserData(ctx)
	if err != nil {
		return err
	}

	apiKeyDetails := userData.APIKeys[hashedKey]
	apiKeyDetails.LastUsed = time.Now()

	userData.APIKeys[hashedKey] = apiKeyDetails

	err = dwr.SetUserData(ctx, userData)

	return err
}

func (dwr DynamoDB) AddUserAPIKey(ctx context.Context, hashedKey string, apiKeyDetails *mTypes.APIKeyDetails) error {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)
	if userid == "" {
		// empty user is anonymous
		return zerr.ErrUserDataNotAllowed
	}

	userData, err := dwr.GetUserData(ctx)
	if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
		return fmt.Errorf("metaDB: error while getting userData for identity %s %w", userid, err)
	}

	if userData.APIKeys == nil {
		userData.APIKeys = make(map[string]mTypes.APIKeyDetails)
	}

	userData.APIKeys[hashedKey] = *apiKeyDetails

	userAttributeValue, err := attributevalue.Marshal(userData)
	if err != nil {
		return err
	}

	_, err = dwr.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{
				// Update UserData
				Update: &types.Update{
					ExpressionAttributeNames: map[string]string{
						"#UP": "UserData",
					},
					ExpressionAttributeValues: map[string]types.AttributeValue{
						":UserData": userAttributeValue,
					},
					Key: map[string]types.AttributeValue{
						"Identity": &types.AttributeValueMemberS{
							Value: userid,
						},
					},
					TableName:        aws.String(dwr.UserDataTablename),
					UpdateExpression: aws.String("SET #UP = :UserData"),
				},
			},
			{
				// Update APIKeyInfo
				Update: &types.Update{
					ExpressionAttributeNames: map[string]string{
						"#EM": "Identity",
					},
					ExpressionAttributeValues: map[string]types.AttributeValue{
						":Identity": &types.AttributeValueMemberS{Value: userid},
					},
					Key: map[string]types.AttributeValue{
						"HashedKey": &types.AttributeValueMemberS{
							Value: hashedKey,
						},
					},
					TableName:        aws.String(dwr.APIKeyTablename),
					UpdateExpression: aws.String("SET #EM = :Identity"),
				},
			},
		},
	})

	return err
}

func (dwr DynamoDB) DeleteUserAPIKey(ctx context.Context, keyID string) error {
	userData, err := dwr.GetUserData(ctx)
	if err != nil {
		return fmt.Errorf("metaDB: error while getting userData %w", err)
	}

	for hash, apiKeyDetails := range userData.APIKeys {
		if apiKeyDetails.UUID == keyID {
			delete(userData.APIKeys, hash)

			_, err = dwr.Client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
				TableName: aws.String(dwr.APIKeyTablename),
				Key: map[string]types.AttributeValue{
					"HashedKey": &types.AttributeValueMemberS{Value: hash},
				},
			})
			if err != nil {
				return fmt.Errorf("metaDB: error while deleting userAPIKey entry for hash %s %w", hash, err)
			}

			err := dwr.SetUserData(ctx, userData)

			return err
		}
	}

	return nil
}

func (dwr DynamoDB) GetUserAPIKeyInfo(hashedKey string) (string, error) {
	var userid string

	resp, err := dwr.Client.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.APIKeyTablename),
		Key: map[string]types.AttributeValue{
			"HashedKey": &types.AttributeValueMemberS{Value: hashedKey},
		},
	})
	if err != nil {
		return "", err
	}

	if resp.Item == nil {
		return "", zerr.ErrUserAPIKeyNotFound
	}

	err = attributevalue.Unmarshal(resp.Item["Identity"], &userid)
	if err != nil {
		return "", err
	}

	return userid, nil
}

func (dwr DynamoDB) GetUserData(ctx context.Context) (mTypes.UserData, error) {
	var userData mTypes.UserData

	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return userData, err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)
	if userid == "" {
		// empty user is anonymous
		return userData, zerr.ErrUserDataNotAllowed
	}

	resp, err := dwr.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(dwr.UserDataTablename),
		Key: map[string]types.AttributeValue{
			"Identity": &types.AttributeValueMemberS{Value: userid},
		},
	})
	if err != nil {
		return mTypes.UserData{}, err
	}

	if resp.Item == nil {
		return mTypes.UserData{}, zerr.ErrUserDataNotFound
	}

	err = attributevalue.Unmarshal(resp.Item["UserData"], &userData)
	if err != nil {
		return mTypes.UserData{}, err
	}

	return userData, nil
}

func (dwr DynamoDB) SetUserData(ctx context.Context, userData mTypes.UserData) error {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)
	if userid == "" {
		// empty user is anonymous
		return zerr.ErrUserDataNotAllowed
	}

	userAttributeValue, err := attributevalue.Marshal(userData)
	if err != nil {
		return err
	}

	_, err = dwr.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#UP": "UserData",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":UserData": userAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"Identity": &types.AttributeValueMemberS{
				Value: userid,
			},
		},
		TableName:        aws.String(dwr.UserDataTablename),
		UpdateExpression: aws.String("SET #UP = :UserData"),
	})

	return err
}

func (dwr DynamoDB) DeleteUserData(ctx context.Context) error {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)
	if userid == "" {
		// empty user is anonymous
		return zerr.ErrUserDataNotAllowed
	}

	_, err = dwr.Client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(dwr.UserDataTablename),
		Key: map[string]types.AttributeValue{
			"Identity": &types.AttributeValueMemberS{Value: userid},
		},
	})

	return err
}
