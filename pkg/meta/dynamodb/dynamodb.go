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
	"zotregistry.io/zot/pkg/api/constants"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/common"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/meta/version"
	reqCtx "zotregistry.io/zot/pkg/requestcontext"
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
	imgTrustStore         mTypes.ImageTrustStore
	Log                   log.Logger
}

func New(
	client *dynamodb.Client, params DBDriverParameters, log log.Logger,
) (*DynamoDB, error) {
	dynamoWrapper := DynamoDB{
		Client:                client,
		RepoMetaTablename:     params.RepoMetaTablename,
		ManifestDataTablename: params.ManifestDataTablename,
		IndexDataTablename:    params.IndexDataTablename,
		VersionTablename:      params.VersionTablename,
		UserDataTablename:     params.UserDataTablename,
		APIKeyTablename:       params.APIKeyTablename,
		Patches:               version.GetDynamoDBPatches(),
		imgTrustStore:         nil,
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

func (dwr *DynamoDB) ImageTrustStore() mTypes.ImageTrustStore {
	return dwr.imgTrustStore
}

func (dwr *DynamoDB) SetImageTrustStore(imgTrustStore mTypes.ImageTrustStore) {
	dwr.imgTrustStore = imgTrustStore
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

	referrers := repoMeta.Referrers[referredDigest.String()]

	for i := range referrers {
		if referrers[i].Digest == referrer.Digest {
			return nil
		}
	}

	referrers = append(referrers, referrer)

	repoMeta.Referrers[referredDigest.String()] = referrers

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

/*
	RemoveRepoReference removes the tag from RepoMetadata if the reference is a tag,

it also removes its corresponding digest from Statistics, Signatures and Referrers if there are no tags
pointing to it.
If the reference is a digest then it will remove the digest from Statistics, Signatures and Referrers only
if there are no tags pointing to the digest, otherwise it's noop.
*/
func (dwr *DynamoDB) RemoveRepoReference(repo, reference string, manifestDigest godigest.Digest,
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

	if !common.ReferenceIsDigest(reference) {
		delete(repoMeta.Tags, reference)
	} else {
		// find all tags pointing to this digest
		tags := []string{}
		for tag, desc := range repoMeta.Tags {
			if desc.Digest == reference {
				tags = append(tags, tag)
			}
		}

		// remove all tags
		for _, tag := range tags {
			delete(repoMeta.Tags, tag)
		}
	}

	/* try to find at least one tag pointing to manifestDigest
	if not found then we can also remove everything related to this digest */
	var foundTag bool

	for _, desc := range repoMeta.Tags {
		if desc.Digest == manifestDigest.String() {
			foundTag = true
		}
	}

	if !foundTag {
		delete(repoMeta.Statistics, manifestDigest.String())
		delete(repoMeta.Signatures, manifestDigest.String())
		delete(repoMeta.Referrers, manifestDigest.String())
	}

	err = dwr.SetRepoMeta(repo, repoMeta)

	return err
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
	imgTrustStore := dwr.ImageTrustStore()

	if imgTrustStore == nil {
		return nil
	}

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
				author, date, isTrusted, _ := imgTrustStore.VerifySignature(sigType, layerInfo.LayerContent, layerInfo.SignatureKey,
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
		if sygMeta.SignatureType == zcommon.NotationSignature {
			signatureSlice = append(signatureSlice, mTypes.SignatureInfo{
				SignatureManifestDigest: sygMeta.SignatureDigest,
				LayersInfo:              sygMeta.LayersInfo,
			})
		} else if sygMeta.SignatureType == zcommon.CosignSignature {
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
	filter func(repoMeta mTypes.RepoMetadata) bool,
) ([]mTypes.RepoMetadata, error) {
	var (
		foundRepos                = []mTypes.RepoMetadata{}
		repoMetaAttributeIterator AttributesIterator
	)

	repoMetaAttributeIterator = NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			return []mTypes.RepoMetadata{}, err
		}

		var repoMeta mTypes.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []mTypes.RepoMetadata{}, err
		}

		if ok, err := reqCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		if filter(repoMeta) {
			foundRepos = append(foundRepos, repoMeta)
		}
	}

	return foundRepos, err
}

func (dwr *DynamoDB) SearchRepos(ctx context.Context, searchText string,
) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error) {
	var (
		repos                     = []mTypes.RepoMetadata{}
		manifestMetadataMap       = make(map[string]mTypes.ManifestMetadata)
		indexDataMap              = make(map[string]mTypes.IndexData)
		repoMetaAttributeIterator AttributesIterator

		userBookmarks = getUserBookmarks(ctx, dwr)
		userStars     = getUserStars(ctx, dwr)
	)

	repoMetaAttributeIterator = NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
				err
		}

		var repoMeta mTypes.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
				err
		}

		if ok, err := reqCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		rank := common.RankRepoName(searchText, repoMeta.Name)
		if rank == -1 {
			continue
		}

		repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repoMeta.Name)
		repoMeta.IsStarred = zcommon.Contains(userStars, repoMeta.Name)
		repoMeta.Rank = rank

		for _, descriptor := range repoMeta.Tags {
			switch descriptor.MediaType {
			case ispec.MediaTypeImageManifest:
				manifestDigest := descriptor.Digest

				manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifestDigest, //nolint:contextcheck
					manifestMetadataMap)
				if err != nil {
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
						err
				}

				manifestMetadataMap[descriptor.Digest] = manifestMeta
			case ispec.MediaTypeImageIndex:
				indexData, err := dwr.fetchIndexDataWithCheck(descriptor.Digest, indexDataMap) //nolint:contextcheck
				if err != nil {
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
						err
				}

				var indexContent ispec.Index

				err = json.Unmarshal(indexData.IndexBlob, &indexContent)
				if err != nil {
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
						fmt.Errorf("metadb: error while unmarshaling index content for digest %s %w", descriptor.Digest, err)
				}

				for _, manifest := range indexContent.Manifests {
					manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifest.Digest.String(), //nolint: contextcheck
						manifestMetadataMap)
					if err != nil {
						return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
							err
					}

					manifestMetadataMap[manifest.Digest.String()] = manifestMeta
				}

				indexDataMap[descriptor.Digest] = indexData
			default:
				dwr.Log.Error().Str("mediaType", descriptor.MediaType).Msg("Unsupported media type")

				continue
			}
		}

		repos = append(repos, repoMeta)
	}

	return repos, manifestMetadataMap, indexDataMap, nil
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

func (dwr *DynamoDB) FilterTags(ctx context.Context, filterFunc mTypes.FilterFunc,
) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error,
) {
	var (
		foundRepos                = make([]mTypes.RepoMetadata, 0)
		manifestMetadataMap       = make(map[string]mTypes.ManifestMetadata)
		indexDataMap              = make(map[string]mTypes.IndexData)
		repoMetaAttributeIterator AttributesIterator
		userBookmarks             = getUserBookmarks(ctx, dwr)
		userStars                 = getUserStars(ctx, dwr)
		aggregateError            error
	)

	repoMetaAttributeIterator = NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)
	if err != nil {
		return foundRepos, manifestMetadataMap, indexDataMap, err
	}

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			aggregateError = errors.Join(aggregateError, err)

			continue
		}

		var repoMeta mTypes.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			aggregateError = errors.Join(aggregateError, err)

			continue
		}

		if ok, err := reqCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
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
					err = fmt.Errorf("metadb: error while unmashaling manifest metadata for digest %s \n%w", manifestDigest, err)
					aggregateError = errors.Join(aggregateError, err)

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
					err = fmt.Errorf("metadb: error while getting index data for digest %s %w", indexDigest, err)
					aggregateError = errors.Join(aggregateError, err)

					continue
				}

				var indexContent ispec.Index

				err = json.Unmarshal(indexData.IndexBlob, &indexContent)
				if err != nil {
					err = fmt.Errorf("metadb: error while unmashaling index content for digest %s %w", indexDigest, err)
					aggregateError = errors.Join(aggregateError, err)

					continue
				}

				matchedManifests := []ispec.Descriptor{}

				for _, manifest := range indexContent.Manifests {
					manifestDigest := manifest.Digest.String()

					manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifestDigest, //nolint:contextcheck
						manifestMetadataMap)
					if err != nil {
						err = fmt.Errorf("%w metadb: error while getting manifest data for digest %s", err, manifestDigest)
						aggregateError = errors.Join(aggregateError, err)

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
						aggregateError = errors.Join(aggregateError, err)

						continue
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

		foundRepos = append(foundRepos, repoMeta)
	}

	return foundRepos, manifestMetadataMap, indexDataMap, aggregateError
}

func (dwr *DynamoDB) FilterRepos(ctx context.Context, filter mTypes.FilterRepoFunc,
) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error) {
	var (
		foundRepos                = []mTypes.RepoMetadata{}
		repoMetaAttributeIterator AttributesIterator
		userBookmarks             = getUserBookmarks(ctx, dwr)
		userStars                 = getUserStars(ctx, dwr)
	)

	repoMetaAttributeIterator = NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
				err
		}

		var repoMeta mTypes.RepoMetadata

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
		if err != nil {
			return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
				err
		}

		if ok, err := reqCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
			continue
		}

		repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repoMeta.Name)
		repoMeta.IsStarred = zcommon.Contains(userStars, repoMeta.Name)

		if filter(repoMeta) {
			foundRepos = append(foundRepos, repoMeta)
		}
	}

	foundManifestMetadataMap, foundIndexDataMap, err := common.FetchDataForRepos(dwr, foundRepos)

	return foundRepos, foundManifestMetadataMap, foundIndexDataMap, err
}

func (dwr *DynamoDB) SearchTags(ctx context.Context, searchText string,
) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
	error,
) {
	var (
		foundRepos                = make([]mTypes.RepoMetadata, 0, 1)
		manifestMetadataMap       = make(map[string]mTypes.ManifestMetadata)
		indexDataMap              = make(map[string]mTypes.IndexData)
		repoMetaAttributeIterator AttributesIterator
		userBookmarks             = getUserBookmarks(ctx, dwr)
		userStars                 = getUserStars(ctx, dwr)
	)

	repoMetaAttributeIterator = NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMetadata", 0, dwr.Log,
	)

	searchedRepo, searchedTag, err := common.GetRepoTag(searchText)
	if err != nil {
		return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
			fmt.Errorf("metadb: error while parsing search text, invalid format %w", err)
	}

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)
	if err != nil {
		return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
			err
	}

	var repoMeta mTypes.RepoMetadata

	err = attributevalue.Unmarshal(repoMetaAttribute, &repoMeta)
	if err != nil {
		return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
			err
	}

	if ok, err := reqCtx.RepoIsUserAvailable(ctx, repoMeta.Name); !ok || err != nil {
		return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
			err
	}

	if repoMeta.Name != searchedRepo {
		return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
			err
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
					fmt.Errorf("metadb: error while unmashaling manifest metadata for digest %s %w", descriptor.Digest, err)
			}

			manifestMetadataMap[descriptor.Digest] = manifestMeta
		case ispec.MediaTypeImageIndex:
			indexDigest := descriptor.Digest

			indexData, err := dwr.fetchIndexDataWithCheck(indexDigest, indexDataMap) //nolint:contextcheck
			if err != nil {
				return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
					fmt.Errorf("%w", err)
			}

			var indexContent ispec.Index

			err = json.Unmarshal(indexData.IndexBlob, &indexContent)
			if err != nil {
				return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
					fmt.Errorf("metadb: error while unmashaling index content for digest %s %w", indexDigest, err)
			}

			for _, manifest := range indexContent.Manifests {
				manifestDigest := manifest.Digest.String()

				manifestMeta, err := dwr.fetchManifestMetaWithCheck(repoMeta.Name, manifestDigest, //nolint:contextcheck
					manifestMetadataMap)
				if err != nil {
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
						fmt.Errorf("%w", err)
				}

				manifestMetadataMap[manifestDigest] = manifestMeta
			}

			indexDataMap[indexDigest] = indexData
		default:
			dwr.Log.Error().Str("mediaType", descriptor.MediaType).Msg("Unsupported media type")

			continue
		}
	}

	if len(matchedTags) == 0 {
		return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
			err
	}

	repoMeta.Tags = matchedTags

	foundRepos = append(foundRepos, repoMeta)

	return foundRepos, manifestMetadataMap, indexDataMap, err
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
	if err != nil {
		if strings.Contains(err.Error(), "Table already exists") {
			return nil
		}

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
	if err != nil {
		if strings.Contains(err.Error(), "Table already exists") {
			return nil
		}

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
	if err != nil {
		if strings.Contains(err.Error(), "Table already exists") {
			return nil
		}

		return err
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

	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return mTypes.NotChanged, err
	}

	if userAc.IsAnonymous() || !userAc.Can(constants.ReadPermission, repo) {
		return mTypes.NotChanged, zerr.ErrUserDataNotAllowed
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

	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return mTypes.NotChanged, err
	}

	if userAc.IsAnonymous() || !userAc.Can(constants.ReadPermission, repo) {
		return mTypes.NotChanged, zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

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
	if err != nil {
		if strings.Contains(err.Error(), "Table already exists") {
			return nil
		}

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
	if err != nil {
		if strings.Contains(err.Error(), "Table already exists") {
			return nil
		}

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

func (dwr *DynamoDB) IsAPIKeyExpired(ctx context.Context, hashedKey string) (bool, error) {
	userData, err := dwr.GetUserData(ctx)
	if err != nil {
		return false, err
	}

	var isExpired bool

	apiKeyDetails := userData.APIKeys[hashedKey]
	if apiKeyDetails.IsExpired {
		isExpired = true

		return isExpired, nil
	}

	// if expiresAt is not nil value
	if !apiKeyDetails.ExpirationDate.Equal(time.Time{}) && time.Now().After(apiKeyDetails.ExpirationDate) {
		isExpired = true
		apiKeyDetails.IsExpired = true
	}

	userData.APIKeys[hashedKey] = apiKeyDetails

	err = dwr.SetUserData(ctx, userData)

	return isExpired, err
}

func (dwr DynamoDB) UpdateUserAPIKeyLastUsed(ctx context.Context, hashedKey string) error {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return err
	}

	if userAc.IsAnonymous() {
		return zerr.ErrUserDataNotAllowed
	}

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

func (dwr DynamoDB) GetUserAPIKeys(ctx context.Context) ([]mTypes.APIKeyDetails, error) {
	apiKeys := make([]mTypes.APIKeyDetails, 0)

	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if userAc.IsAnonymous() {
		return nil, zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	userData, err := dwr.GetUserData(ctx)
	if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
		return nil, fmt.Errorf("metaDB: error while getting userData for identity %s %w", userid, err)
	}

	for hashedKey, apiKeyDetails := range userData.APIKeys {
		// if expiresAt is not nil value
		if !apiKeyDetails.ExpirationDate.Equal(time.Time{}) && time.Now().After(apiKeyDetails.ExpirationDate) {
			apiKeyDetails.IsExpired = true
		}

		userData.APIKeys[hashedKey] = apiKeyDetails

		err = dwr.SetUserData(ctx, userData)
		if err != nil {
			return nil, err
		}

		apiKeys = append(apiKeys, apiKeyDetails)
	}

	return apiKeys, nil
}

func (dwr DynamoDB) AddUserAPIKey(ctx context.Context, hashedKey string, apiKeyDetails *mTypes.APIKeyDetails) error {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return err
	}

	if userAc.IsAnonymous() {
		return zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

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

	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return userData, err
	}

	if userAc.IsAnonymous() {
		return userData, zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

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
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return err
	}

	if userAc.IsAnonymous() {
		return zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

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
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return err
	}

	if userAc.IsAnonymous() {
		return zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	_, err = dwr.Client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(dwr.UserDataTablename),
		Key: map[string]types.AttributeValue{
			"Identity": &types.AttributeValueMemberS{Value: userid},
		},
	})

	return err
}
