package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/compat"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta/common"
	mConvert "zotregistry.dev/zot/v2/pkg/meta/convert"
	proto_go "zotregistry.dev/zot/v2/pkg/meta/proto/gen"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/meta/version"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
)

type DynamoDB struct {
	Client             *dynamodb.Client
	APIKeyTablename    string
	RepoMetaTablename  string
	RepoBlobsTablename string
	ImageMetaTablename string
	UserDataTablename  string
	VersionTablename   string
	Patches            []func(client *dynamodb.Client, tableNames map[string]string) error
	imgTrustStore      mTypes.ImageTrustStore
	Log                log.Logger
}

func New(client *dynamodb.Client, params DBDriverParameters, log log.Logger,
) (*DynamoDB, error) {
	dynamoWrapper := DynamoDB{
		Client:             client,
		VersionTablename:   params.VersionTablename,
		UserDataTablename:  params.UserDataTablename,
		APIKeyTablename:    params.APIKeyTablename,
		RepoMetaTablename:  params.RepoMetaTablename,
		ImageMetaTablename: params.ImageMetaTablename,
		RepoBlobsTablename: params.RepoBlobsInfoTablename,
		Patches:            version.GetDynamoDBPatches(),
		imgTrustStore:      nil,
		Log:                log,
	}

	err := dynamoWrapper.createVersionTable()
	if err != nil {
		return nil, err
	}

	err = dynamoWrapper.createTable(dynamoWrapper.RepoMetaTablename)
	if err != nil {
		return nil, err
	}

	err = dynamoWrapper.createTable(dynamoWrapper.RepoBlobsTablename)
	if err != nil {
		return nil, err
	}

	err = dynamoWrapper.createTable(dynamoWrapper.ImageMetaTablename)
	if err != nil {
		return nil, err
	}

	err = dynamoWrapper.createTable(dynamoWrapper.UserDataTablename)
	if err != nil {
		return nil, err
	}

	err = dynamoWrapper.createTable(dynamoWrapper.APIKeyTablename)
	if err != nil {
		return nil, err
	}

	// Using the Config value, create the DynamoDB client
	return &dynamoWrapper, nil
}

func (dwr *DynamoDB) GetAllRepoNames() ([]string, error) {
	ctx := context.Background()
	attributeIterator := NewBaseDynamoAttributesIterator(dwr.Client, dwr.RepoMetaTablename, "TableKey", 0, dwr.Log)

	repoNames := []string{}

	repoNameAttribute, err := attributeIterator.First(ctx)

	for ; repoNameAttribute != nil; repoNameAttribute, err = attributeIterator.Next(ctx) {
		if err != nil {
			return []string{}, err
		}

		var repoName string

		err := attributevalue.Unmarshal(repoNameAttribute, &repoName)
		if err != nil {
			continue
		}

		repoNames = append(repoNames, repoName)
	}

	return repoNames, nil
}

func (dwr *DynamoDB) GetRepoLastUpdated(repo string) time.Time {
	resp, err := dwr.Client.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.RepoBlobsTablename),
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{Value: repo},
		},
		ProjectionExpression: aws.String("RepoLastUpdated"),
	})
	if err != nil {
		return time.Time{}
	}

	protoRepoLastUpdated := &timestamppb.Timestamp{}
	repoLastUpdatedBlob := []byte{}

	if resp.Item != nil {
		// Check if RepoLastUpdated attribute exists in the item
		if _, exists := resp.Item["RepoLastUpdated"]; !exists {
			return time.Time{}
		}

		err = attributevalue.Unmarshal(resp.Item["RepoLastUpdated"], &repoLastUpdatedBlob)
		if err != nil {
			return time.Time{}
		}

		if len(repoLastUpdatedBlob) > 0 {
			err := proto.Unmarshal(repoLastUpdatedBlob, protoRepoLastUpdated)
			if err != nil {
				return time.Time{}
			}
		} else {
			// Empty blob means no timestamp was set
			return time.Time{}
		}
	} else {
		// Item doesn't exist, return zero time
		return time.Time{}
	}

	// Check if the timestamp is zero before converting
	if protoRepoLastUpdated.Seconds == 0 && protoRepoLastUpdated.Nanos == 0 {
		return time.Time{}
	}

	lastUpdated := *mConvert.GetTime(protoRepoLastUpdated)

	return lastUpdated
}

func (dwr *DynamoDB) ImageTrustStore() mTypes.ImageTrustStore {
	return dwr.imgTrustStore
}

func (dwr *DynamoDB) SetImageTrustStore(imgTrustStore mTypes.ImageTrustStore) {
	dwr.imgTrustStore = imgTrustStore
}

func (dwr *DynamoDB) SetProtoImageMeta(digest godigest.Digest, protoImageMeta *proto_go.ImageMeta) error {
	bytes, err := proto.Marshal(protoImageMeta)
	if err != nil {
		return err
	}

	mdAttributeValue, err := attributevalue.Marshal(bytes)
	if err != nil {
		return err
	}

	_, err = dwr.Client.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#IM": "ImageMeta",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":ImageMeta": mdAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{
				Value: digest.String(),
			},
		},
		TableName:        aws.String(dwr.ImageMetaTablename),
		UpdateExpression: aws.String("SET #IM = :ImageMeta"),
	})

	return err
}

func (dwr *DynamoDB) SetImageMeta(digest godigest.Digest, imageMeta mTypes.ImageMeta) error {
	return dwr.SetProtoImageMeta(digest, mConvert.GetProtoImageMeta(imageMeta))
}

func (dwr *DynamoDB) GetProtoImageMeta(ctx context.Context, digest godigest.Digest) (*proto_go.ImageMeta, error) {
	resp, err := dwr.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(dwr.ImageMetaTablename),
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{Value: digest.String()},
		},
	})
	if err != nil {
		return nil, err
	}

	blob := []byte{}

	if resp.Item == nil {
		return nil, zerr.ErrImageMetaNotFound
	}

	err = attributevalue.Unmarshal(resp.Item["ImageMeta"], &blob)
	if err != nil {
		return nil, err
	}

	imageMeta := &proto_go.ImageMeta{}

	err = proto.Unmarshal(blob, imageMeta)
	if err != nil {
		return nil, err
	}

	return imageMeta, nil
}

func (dwr *DynamoDB) getAllContainedMeta(ctx context.Context, imageIndexData *proto_go.ImageMeta,
) ([]*proto_go.ImageMeta, []*proto_go.ManifestMeta, error) {
	manifestDataList := make([]*proto_go.ManifestMeta, 0, len(imageIndexData.Index.Index.Manifests))
	imageMetaList := make([]*proto_go.ImageMeta, 0, len(imageIndexData.Index.Index.Manifests))
	manifestDigests := make([]string, 0, len(imageIndexData.Index.Index.Manifests))

	for _, manifest := range imageIndexData.Index.Index.Manifests {
		if manifest.MediaType != ispec.MediaTypeImageManifest &&
			manifest.MediaType != ispec.MediaTypeImageIndex &&
			!compat.IsCompatibleManifestMediaType(manifest.MediaType) &&
			!compat.IsCompatibleManifestListMediaType(manifest.MediaType) {
			// filter out unexpected media types from the manifest lists,
			// this could be the case of buildkit cache entries for example
			continue
		}

		manifestDigests = append(manifestDigests, manifest.Digest)
	}

	manifestsAttributes, err := dwr.fetchImageMetaAttributesByDigest(ctx, manifestDigests)
	if err != nil {
		return imageMetaList, manifestDataList, err
	}

	for _, manifestAttribute := range manifestsAttributes {
		imageManifestData, err := getProtoImageMetaFromAttribute(manifestAttribute["ImageMeta"])
		if err != nil {
			return imageMetaList, manifestDataList, err
		}

		if imageManifestData.MediaType == ispec.MediaTypeImageManifest ||
			compat.IsCompatibleManifestMediaType(imageManifestData.MediaType) {
			imageMetaList = append(imageMetaList, imageManifestData)
			manifestDataList = append(manifestDataList, imageManifestData.Manifests[0])
		} else if imageManifestData.MediaType == ispec.MediaTypeImageIndex ||
			compat.IsCompatibleManifestListMediaType(imageManifestData.MediaType) {
			partialImageDataList, partialManifestDataList, err := dwr.getAllContainedMeta(ctx, imageManifestData)
			if err != nil {
				return imageMetaList, manifestDataList, err
			}

			imageMetaList = append(imageMetaList, partialImageDataList...)
			manifestDataList = append(manifestDataList, partialManifestDataList...)
		}
	}

	return imageMetaList, manifestDataList, nil
}

func (dwr *DynamoDB) setProtoRepoMeta(repo string, repoMeta *proto_go.RepoMeta) error {
	repoMeta.Name = repo

	repoMetaBlob, err := proto.Marshal(repoMeta)
	if err != nil {
		return err
	}

	repoAttributeValue, err := attributevalue.Marshal(repoMetaBlob)
	if err != nil {
		return err
	}

	_, err = dwr.Client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#RM": "RepoMeta",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":RepoMeta": repoAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{
				Value: repo,
			},
		},
		TableName:        aws.String(dwr.RepoMetaTablename),
		UpdateExpression: aws.String("SET #RM = :RepoMeta"),
	})

	return err
}

func (dwr *DynamoDB) getProtoRepoMeta(ctx context.Context, repo string) (*proto_go.RepoMeta, error) {
	resp, err := dwr.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(dwr.RepoMetaTablename),
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return nil, err
	}

	protoRepoMeta := &proto_go.RepoMeta{
		Name: repo,
	}

	blob := []byte{}

	if resp.Item != nil {
		err = attributevalue.Unmarshal(resp.Item["RepoMeta"], &blob)
		if err != nil {
			return nil, err
		}

		err = proto.Unmarshal(blob, protoRepoMeta)
		if err != nil {
			return nil, err
		}
	}

	if protoRepoMeta.Tags == nil {
		protoRepoMeta.Tags = map[string]*proto_go.TagDescriptor{"": {}}
	}

	if protoRepoMeta.Statistics == nil {
		protoRepoMeta.Statistics = map[string]*proto_go.DescriptorStatistics{"": {}}
	}

	if protoRepoMeta.Signatures == nil {
		protoRepoMeta.Signatures = map[string]*proto_go.ManifestSignatures{"": {}}
	}

	if protoRepoMeta.Referrers == nil {
		protoRepoMeta.Referrers = map[string]*proto_go.ReferrersInfo{"": {}}
	}

	if len(blob) == 0 || resp.Item == nil {
		return protoRepoMeta, zerr.ErrRepoMetaNotFound
	}

	return protoRepoMeta, nil
}

func (dwr *DynamoDB) SetRepoReference(ctx context.Context, repo string, reference string,
	imageMeta mTypes.ImageMeta,
) error {
	if err := common.ValidateRepoReferenceInput(repo, reference, imageMeta.Digest); err != nil {
		return err
	}

	var userid string

	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err == nil {
		userid = userAc.GetUsername()
	}

	// 1. Add image data to db if needed
	protoImageMeta := mConvert.GetProtoImageMeta(imageMeta)

	err = dwr.SetProtoImageMeta(imageMeta.Digest, protoImageMeta) //nolint: contextcheck
	if err != nil {
		return err
	}

	repoMeta, err := dwr.getProtoRepoMeta(ctx, repo)
	if err != nil && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
		return err
	}

	// 2. Referrers
	if subject := mConvert.GetImageSubject(protoImageMeta); subject != nil {
		refInfo := &proto_go.ReferrersInfo{}
		if repoMeta.Referrers[subject.Digest.String()] != nil {
			refInfo = repoMeta.Referrers[subject.Digest.String()]
		}

		foundReferrer := false

		for i := range refInfo.List {
			if refInfo.List[i].Digest == mConvert.GetImageDigestStr(protoImageMeta) {
				foundReferrer = true
				refInfo.List[i].Count += 1

				break
			}
		}

		if !foundReferrer {
			refInfo.List = append(refInfo.List, &proto_go.ReferrerInfo{
				Count:        1,
				MediaType:    protoImageMeta.MediaType,
				Digest:       mConvert.GetImageDigestStr(protoImageMeta),
				ArtifactType: mConvert.GetImageArtifactType(protoImageMeta),
				Size:         mConvert.GetImageManifestSize(protoImageMeta),
				Annotations:  mConvert.GetImageAnnotations(protoImageMeta),
			})
		}

		repoMeta.Referrers[subject.Digest.String()] = refInfo
	}

	// 3. Update tag
	if !common.ReferenceIsDigest(reference) {
		// Set TaggedTimestamp to now if this is a new tag, otherwise preserve existing timestamp
		// For old data without TaggedTimestamp, leave it nil so it falls back to PushTimestamp
		var taggedTimestamp *timestamppb.Timestamp
		if existingTag, exists := repoMeta.Tags[reference]; exists {
			// Tag exists - preserve TaggedTimestamp if present, otherwise leave nil (old data)
			if existingTag.GetTaggedTimestamp() != nil {
				taggedTimestamp = existingTag.GetTaggedTimestamp()
			}
			// else leave taggedTimestamp as nil (old data without TaggedTimestamp)
		} else {
			// New tag - set timestamp to now
			taggedTimestamp = timestamppb.Now()
		}
		repoMeta.Tags[reference] = &proto_go.TagDescriptor{
			Digest:          imageMeta.Digest.String(),
			MediaType:       imageMeta.MediaType,
			TaggedTimestamp: taggedTimestamp,
		}
	}

	digestStr := imageMeta.Digest.String()
	stats, ok := repoMeta.Statistics[digestStr]

	if !ok {
		stats = &proto_go.DescriptorStatistics{
			DownloadCount:     0,
			LastPullTimestamp: &timestamppb.Timestamp{},
			PushTimestamp:     timestamppb.Now(),
			PushedBy:          userid,
		}
		repoMeta.Statistics[digestStr] = stats
	} else {
		if stats.PushTimestamp.AsTime().IsZero() {
			stats.PushTimestamp = timestamppb.Now()
		}

		if userid != "" && stats.PushedBy == "" {
			stats.PushedBy = userid
		}
	}

	if _, ok := repoMeta.Signatures[imageMeta.Digest.String()]; !ok {
		repoMeta.Signatures[imageMeta.Digest.String()] = &proto_go.ManifestSignatures{
			Map: map[string]*proto_go.SignaturesInfo{"": {}},
		}
	}

	if _, ok := repoMeta.Referrers[imageMeta.Digest.String()]; !ok {
		repoMeta.Referrers[imageMeta.Digest.String()] = &proto_go.ReferrersInfo{
			List: []*proto_go.ReferrerInfo{},
		}
	}

	// 4. Blobs
	repoBlobs, err := dwr.getProtoRepoBlobs(ctx, repo)
	if err != nil {
		return err
	}

	repoMeta, repoBlobs = common.AddImageMetaToRepoMeta(repoMeta, repoBlobs, reference, imageMeta)

	err = dwr.setRepoBlobsInfo(repo, repoBlobs) //nolint: contextcheck
	if err != nil {
		return err
	}

	return dwr.setProtoRepoMeta(repo, repoMeta) //nolint: contextcheck
}

func (dwr *DynamoDB) updateRepoLastUpdated(ctx context.Context, repo string, time time.Time) error {
	protoTime := timestamppb.New(time)

	protoTimeBlob, err := proto.Marshal(protoTime)
	if err != nil {
		return err
	}

	mdAttributeValue, err := attributevalue.Marshal(protoTimeBlob)
	if err != nil {
		return err
	}

	_, err = dwr.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#RLU": "RepoLastUpdated",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":RepoLastUpdated": mdAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{
				Value: repo,
			},
		},
		TableName:        aws.String(dwr.RepoBlobsTablename),
		UpdateExpression: aws.String("SET #RLU = :RepoLastUpdated"),
	})

	return err
}

func (dwr *DynamoDB) getProtoRepoBlobs(ctx context.Context, repo string) (*proto_go.RepoBlobs, error) {
	resp, err := dwr.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(dwr.RepoBlobsTablename),
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{Value: repo},
		},
	})
	if err != nil {
		return nil, err
	}

	repoBlobs := &proto_go.RepoBlobs{
		Name: repo,
	}

	repoBlobsBytes := []byte{}

	if resp.Item != nil {
		err = attributevalue.Unmarshal(resp.Item["RepoBlobsInfo"], &repoBlobsBytes)
		if err != nil {
			return nil, err
		}

		if len(repoBlobsBytes) > 0 {
			err := proto.Unmarshal(repoBlobsBytes, repoBlobs)
			if err != nil {
				return nil, err
			}
		}
	}

	if repoBlobs.Blobs == nil {
		repoBlobs.Blobs = map[string]*proto_go.BlobInfo{"": {}}
	}

	return repoBlobs, nil
}

func (dwr *DynamoDB) setRepoBlobsInfo(repo string, repoBlobs *proto_go.RepoBlobs) error {
	protoTime := timestamppb.Now()

	protoTimeBlob, err := proto.Marshal(protoTime)
	if err != nil {
		return err
	}

	timeAttributeValue, err := attributevalue.Marshal(protoTimeBlob)
	if err != nil {
		return err
	}

	bytes, err := proto.Marshal(repoBlobs)
	if err != nil {
		return err
	}

	mdAttributeValue, err := attributevalue.Marshal(bytes)
	if err != nil {
		return err
	}

	_, err = dwr.Client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#RBI": "RepoBlobsInfo",
			"#RLU": "RepoLastUpdated",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":RepoBlobsInfo":   mdAttributeValue,
			":RepoLastUpdated": timeAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{
				Value: repo,
			},
		},
		TableName:        aws.String(dwr.RepoBlobsTablename),
		UpdateExpression: aws.String("SET #RBI = :RepoBlobsInfo, #RLU = :RepoLastUpdated"),
	})

	return err
}

func (dwr *DynamoDB) SearchRepos(ctx context.Context, searchText string) ([]mTypes.RepoMeta, error) {
	repos := []mTypes.RepoMeta{}

	userBookmarks := getUserBookmarks(ctx, dwr)
	userStars := getUserStars(ctx, dwr)

	repoMetaAttributeIterator := NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMeta", 0, dwr.Log,
	)

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			return []mTypes.RepoMeta{}, err
		}

		repoMetaBlob := []byte{}

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMetaBlob)
		if err != nil {
			return []mTypes.RepoMeta{}, err
		}

		protoRepoMeta := &proto_go.RepoMeta{}

		err = proto.Unmarshal(repoMetaBlob, protoRepoMeta)
		if err != nil {
			return []mTypes.RepoMeta{}, err
		}

		if ok, err := reqCtx.RepoIsUserAvailable(ctx, protoRepoMeta.Name); !ok || err != nil {
			continue
		}

		delete(protoRepoMeta.Tags, "")

		if len(protoRepoMeta.Tags) == 0 {
			continue
		}

		rank := common.RankRepoName(searchText, protoRepoMeta.Name)
		if rank == -1 {
			continue
		}

		protoRepoMeta.Rank = int32(rank) //nolint:gosec // ignore overflow
		protoRepoMeta.IsStarred = slices.Contains(userStars, protoRepoMeta.Name)
		protoRepoMeta.IsBookmarked = slices.Contains(userBookmarks, protoRepoMeta.Name)

		repos = append(repos, mConvert.GetRepoMeta(protoRepoMeta))
	}

	return repos, nil
}

func (dwr *DynamoDB) SearchTags(ctx context.Context, searchText string) ([]mTypes.FullImageMeta, error) {
	images := []mTypes.FullImageMeta{}
	userBookmarks := getUserBookmarks(ctx, dwr)
	userStars := getUserStars(ctx, dwr)

	searchedRepo, searchedTag, err := common.GetRepoTag(searchText)
	if err != nil {
		return []mTypes.FullImageMeta{},
			fmt.Errorf("failed to parse search text, invalid format %w", err)
	}

	if ok, err := reqCtx.RepoIsUserAvailable(ctx, searchedRepo); !ok || err != nil {
		return []mTypes.FullImageMeta{}, err
	}

	protoRepoMeta, err := dwr.getProtoRepoMeta(ctx, searchedRepo)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return []mTypes.FullImageMeta{}, nil
		}

		return nil, err
	}

	delete(protoRepoMeta.Tags, "")

	protoRepoMeta.IsBookmarked = slices.Contains(userBookmarks, searchedRepo)
	protoRepoMeta.IsStarred = slices.Contains(userStars, searchedRepo)

	for tag, descriptor := range protoRepoMeta.Tags {
		if !strings.HasPrefix(tag, searchedTag) {
			continue
		}

		var protoImageMeta *proto_go.ImageMeta

		if descriptor.MediaType == ispec.MediaTypeImageManifest || //nolint:gocritic
			compat.IsCompatibleManifestMediaType(descriptor.MediaType) {
			manifestDigest := descriptor.Digest

			imageManifestData, err := dwr.GetProtoImageMeta(ctx, godigest.Digest(manifestDigest))
			if err != nil {
				return []mTypes.FullImageMeta{},
					fmt.Errorf("error fetching manifest meta for manifest with digest %s %w", manifestDigest, err)
			}

			protoImageMeta = imageManifestData
		} else if descriptor.MediaType == ispec.MediaTypeImageIndex ||
			compat.IsCompatibleManifestListMediaType(descriptor.MediaType) {
			indexDigest := godigest.Digest(descriptor.Digest)

			imageIndexData, err := dwr.GetProtoImageMeta(ctx, indexDigest)
			if err != nil {
				return []mTypes.FullImageMeta{},
					fmt.Errorf("error fetching manifest meta for manifest with digest %s %w", indexDigest, err)
			}

			_, manifestDataList, err := dwr.getAllContainedMeta(ctx, imageIndexData)
			if err != nil {
				return []mTypes.FullImageMeta{}, err
			}

			imageIndexData.Manifests = manifestDataList

			protoImageMeta = imageIndexData
		} else {
			dwr.Log.Error().Str("mediaType", descriptor.MediaType).Msg("unsupported media type")

			continue
		}

		images = append(images, mConvert.GetFullImageMetaFromProto(tag, protoRepoMeta, protoImageMeta))
	}

	return images, err
}

func (dwr *DynamoDB) FilterTags(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc,
	filterFunc mTypes.FilterFunc,
) ([]mTypes.FullImageMeta, error) {
	images := []mTypes.FullImageMeta{}
	userBookmarks := getUserBookmarks(ctx, dwr)
	userStars := getUserStars(ctx, dwr)

	var viewError error

	repoMetaAttributeIterator := NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMeta", 0, dwr.Log,
	)

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			viewError = errors.Join(viewError, err)

			continue
		}

		protoRepoMeta, err := getProtoRepoMetaFromAttribute(repoMetaAttribute)
		if err != nil {
			viewError = errors.Join(viewError, err)

			continue
		}

		if ok, err := reqCtx.RepoIsUserAvailable(ctx, protoRepoMeta.Name); !ok || err != nil {
			continue
		}

		protoRepoMeta.IsBookmarked = slices.Contains(userBookmarks, protoRepoMeta.Name)
		protoRepoMeta.IsStarred = slices.Contains(userStars, protoRepoMeta.Name)
		repoMeta := mConvert.GetRepoMeta(protoRepoMeta)

		for tag, descriptor := range repoMeta.Tags {
			if !filterRepoTag(repoMeta.Name, tag) {
				continue
			}

			if descriptor.MediaType == ispec.MediaTypeImageManifest || //nolint:gocritic
				compat.IsCompatibleManifestMediaType(descriptor.MediaType) {
				manifestDigest := descriptor.Digest

				imageManifestData, err := dwr.GetProtoImageMeta(ctx, godigest.Digest(manifestDigest))
				if err != nil {
					viewError = errors.Join(viewError, err)

					continue
				}

				imageMeta := mConvert.GetImageMeta(imageManifestData)

				if filterFunc(repoMeta, imageMeta) {
					images = append(images, mConvert.GetFullImageMetaFromProto(tag, protoRepoMeta, imageManifestData))
				}
			} else if descriptor.MediaType == ispec.MediaTypeImageIndex ||
				compat.IsCompatibleManifestListMediaType(descriptor.MediaType) {
				indexDigest := descriptor.Digest

				protoImageIndexMeta, err := dwr.GetProtoImageMeta(ctx, godigest.Digest(indexDigest))
				if err != nil {
					viewError = errors.Join(viewError, err)

					continue
				}

				imageIndexMeta := mConvert.GetImageMeta(protoImageIndexMeta)
				matchedManifests := []*proto_go.ManifestMeta{}

				imageManifestDataList, _, err := dwr.getAllContainedMeta(context.Background(), protoImageIndexMeta)
				if err != nil {
					viewError = errors.Join(viewError, err)

					continue
				}

				for _, imageManifestData := range imageManifestDataList {
					imageMeta := mConvert.GetImageMeta(imageManifestData)
					partialImageMeta := common.GetPartialImageMeta(imageIndexMeta, imageMeta)

					if filterFunc(repoMeta, partialImageMeta) {
						matchedManifests = append(matchedManifests, imageManifestData.Manifests[0])
					}
				}

				if len(matchedManifests) > 0 {
					protoImageIndexMeta.Manifests = matchedManifests

					images = append(images, mConvert.GetFullImageMetaFromProto(tag, protoRepoMeta, protoImageIndexMeta))
				}
			} else {
				dwr.Log.Error().Str("mediaType", descriptor.MediaType).Msg("unsupported media type")

				continue
			}
		}
	}

	viewError = errors.Join(viewError, err)

	return images, viewError
}

func getProtoRepoMetaFromAttribute(repoMetaAttribute types.AttributeValue) (*proto_go.RepoMeta, error) {
	blob := []byte{}

	err := attributevalue.Unmarshal(repoMetaAttribute, &blob)
	if err != nil {
		return nil, err
	}

	protoRepoMeta := &proto_go.RepoMeta{}

	err = proto.Unmarshal(blob, protoRepoMeta)
	if err != nil {
		return nil, err
	}

	return protoRepoMeta, nil
}

func getProtoImageMetaFromAttribute(imageMetaAttribute types.AttributeValue) (*proto_go.ImageMeta, error) {
	blob := []byte{}

	err := attributevalue.Unmarshal(imageMetaAttribute, &blob)
	if err != nil {
		return nil, err
	}

	protoImageMeta := &proto_go.ImageMeta{}

	err = proto.Unmarshal(blob, protoImageMeta)
	if err != nil {
		return nil, err
	}

	return protoImageMeta, nil
}

func (dwr *DynamoDB) ResetRepoReferences(repo string, tagsToKeep map[string]bool) error {
	protoRepoMeta, err := dwr.getProtoRepoMeta(context.Background(), repo)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			// Repo doesn't exist, nothing to reset
			return nil
		}

		return err
	}

	// Preserve tags that are in tagsToKeep, remove others
	preservedTags := make(map[string]*proto_go.TagDescriptor)
	if tagsToKeep != nil {
		for tag, descriptor := range protoRepoMeta.Tags {
			// Keep the tag if it's in tagsToKeep, or if it's the empty key (internal use)
			if tag == "" || tagsToKeep[tag] {
				preservedTags[tag] = descriptor
			}
		}
	}
	// Ensure empty key exists for internal use
	if _, exists := preservedTags[""]; !exists {
		preservedTags[""] = &proto_go.TagDescriptor{}
	}

	return dwr.setProtoRepoMeta(repo, &proto_go.RepoMeta{
		Name:       repo,
		Statistics: protoRepoMeta.Statistics,
		Stars:      protoRepoMeta.Stars,
		Tags:       preservedTags,
		Referrers:  map[string]*proto_go.ReferrersInfo{"": {}},
		Signatures: map[string]*proto_go.ManifestSignatures{"": {Map: map[string]*proto_go.SignaturesInfo{"": {}}}},
	})
}

func (dwr *DynamoDB) GetRepoMeta(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
	protoRepoMeta, err := dwr.getProtoRepoMeta(ctx, repo)
	if err != nil {
		return mTypes.RepoMeta{}, err
	}

	delete(protoRepoMeta.Tags, "")

	userBookmarks := getUserBookmarks(ctx, dwr)
	userStars := getUserStars(ctx, dwr)

	protoRepoMeta.IsBookmarked = slices.Contains(userBookmarks, repo)
	protoRepoMeta.IsStarred = slices.Contains(userStars, repo)

	return mConvert.GetRepoMeta(protoRepoMeta), nil
}

func (dwr *DynamoDB) GetFullImageMeta(ctx context.Context, repo string, tag string) (mTypes.FullImageMeta, error) {
	protoRepoMeta, err := dwr.getProtoRepoMeta(ctx, repo)
	if err != nil {
		return mTypes.FullImageMeta{}, err
	}

	delete(protoRepoMeta.Tags, "")

	bookmarks, stars := dwr.getUserBookmarksAndStars(ctx)

	protoRepoMeta.IsBookmarked = slices.Contains(bookmarks, repo)
	protoRepoMeta.IsStarred = slices.Contains(stars, repo)

	descriptor, ok := protoRepoMeta.Tags[tag]
	if !ok {
		return mTypes.FullImageMeta{}, zerr.ErrImageMetaNotFound
	}

	protoImageMeta, err := dwr.GetProtoImageMeta(ctx, godigest.Digest(descriptor.Digest))
	if err != nil {
		return mTypes.FullImageMeta{}, err
	}

	if protoImageMeta.MediaType == ispec.MediaTypeImageIndex ||
		compat.IsCompatibleManifestListMediaType(protoImageMeta.MediaType) {
		_, manifestDataList, err := dwr.getAllContainedMeta(ctx, protoImageMeta)
		if err != nil {
			return mTypes.FullImageMeta{}, err
		}

		protoImageMeta.Manifests = manifestDataList
	}

	return mConvert.GetFullImageMetaFromProto(tag, protoRepoMeta, protoImageMeta), nil
}

func (dwr *DynamoDB) getUserBookmarksAndStars(ctx context.Context) ([]string, []string) {
	userData, err := dwr.GetUserData(ctx)
	if err != nil {
		return []string{}, []string{}
	}

	return userData.BookmarkedRepos, userData.StarredRepos
}

func (dwr *DynamoDB) GetImageMeta(digest godigest.Digest) (mTypes.ImageMeta, error) {
	protoImageMeta, err := dwr.GetProtoImageMeta(context.Background(), digest)
	if err != nil {
		return mTypes.ImageMeta{}, err
	}

	if protoImageMeta.MediaType == ispec.MediaTypeImageIndex ||
		compat.IsCompatibleManifestListMediaType(protoImageMeta.MediaType) {
		_, manifestDataList, err := dwr.getAllContainedMeta(context.Background(), protoImageMeta)
		if err != nil {
			return mTypes.ImageMeta{}, err
		}

		protoImageMeta.Manifests = manifestDataList
	}

	return mConvert.GetImageMeta(protoImageMeta), nil
}

func (dwr *DynamoDB) GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta mTypes.RepoMeta) bool,
) ([]mTypes.RepoMeta, error) {
	var (
		foundRepos                = []mTypes.RepoMeta{}
		repoMetaAttributeIterator AttributesIterator
	)

	repoMetaAttributeIterator = NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMeta", 0, dwr.Log,
	)

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			return []mTypes.RepoMeta{}, err
		}

		repoMetaBlob := []byte{}

		err := attributevalue.Unmarshal(repoMetaAttribute, &repoMetaBlob)
		if err != nil {
			return []mTypes.RepoMeta{}, err
		}

		protoRepoMeta := &proto_go.RepoMeta{}

		err = proto.Unmarshal(repoMetaBlob, protoRepoMeta)
		if err != nil {
			return []mTypes.RepoMeta{}, err
		}

		delete(protoRepoMeta.Tags, "")

		if ok, err := reqCtx.RepoIsUserAvailable(ctx, protoRepoMeta.Name); !ok || err != nil {
			continue
		}

		repoMeta := mConvert.GetRepoMeta(protoRepoMeta)

		if filter(repoMeta) {
			foundRepos = append(foundRepos, repoMeta)
		}
	}

	return foundRepos, err
}

func (dwr *DynamoDB) FilterRepos(ctx context.Context, acceptName mTypes.FilterRepoNameFunc,
	filterFunc mTypes.FilterFullRepoFunc,
) ([]mTypes.RepoMeta, error) {
	repos := []mTypes.RepoMeta{}
	userBookmarks := getUserBookmarks(ctx, dwr)
	userStars := getUserStars(ctx, dwr)

	repoMetaAttributeIterator := NewBaseDynamoAttributesIterator(
		dwr.Client, dwr.RepoMetaTablename, "RepoMeta", 0, dwr.Log,
	)

	repoMetaAttribute, err := repoMetaAttributeIterator.First(ctx)

	for ; repoMetaAttribute != nil; repoMetaAttribute, err = repoMetaAttributeIterator.Next(ctx) {
		if err != nil {
			return []mTypes.RepoMeta{},
				err
		}

		protoRepoMeta, err := getProtoRepoMetaFromAttribute(repoMetaAttribute)
		if err != nil {
			return nil, err
		}

		if ok, err := reqCtx.RepoIsUserAvailable(ctx, protoRepoMeta.Name); !ok || err != nil {
			continue
		}

		if !acceptName(protoRepoMeta.Name) {
			continue
		}

		protoRepoMeta.IsBookmarked = slices.Contains(userBookmarks, protoRepoMeta.Name)
		protoRepoMeta.IsStarred = slices.Contains(userStars, protoRepoMeta.Name)

		fullRepoMeta := mConvert.GetRepoMeta(protoRepoMeta)

		if filterFunc(fullRepoMeta) {
			repos = append(repos, fullRepoMeta)
		}
	}

	return repos, err
}

func (dwr *DynamoDB) IncrementRepoStars(repo string) error {
	repoMeta, err := dwr.getProtoRepoMeta(context.Background(), repo)
	if err != nil {
		return err
	}

	repoMeta.Stars++

	return dwr.setProtoRepoMeta(repo, repoMeta)
}

func (dwr *DynamoDB) DecrementRepoStars(repo string) error {
	repoMeta, err := dwr.getProtoRepoMeta(context.Background(), repo)
	if err != nil {
		return err
	}

	if repoMeta.Stars > 0 {
		repoMeta.Stars--
	}

	return dwr.setProtoRepoMeta(repo, repoMeta)
}

func (dwr *DynamoDB) SetRepoMeta(repo string, repoMeta mTypes.RepoMeta) error {
	protoRepoMeta := mConvert.GetProtoRepoMeta(repoMeta)

	err := dwr.updateRepoLastUpdated(context.Background(), repo, time.Time{})
	if err != nil {
		return err
	}

	return dwr.setProtoRepoMeta(repo, protoRepoMeta)
}

func (dwr *DynamoDB) DeleteRepoMeta(repo string) error {
	_, err := dwr.Client.TransactWriteItems(context.Background(), &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{
				Delete: &types.Delete{
					Key: map[string]types.AttributeValue{
						"TableKey": &types.AttributeValueMemberS{
							Value: repo,
						},
					},
					TableName: aws.String(dwr.RepoMetaTablename),
				},
			},
			{
				Delete: &types.Delete{
					Key: map[string]types.AttributeValue{
						"TableKey": &types.AttributeValueMemberS{
							Value: repo,
						},
					},
					TableName: aws.String(dwr.RepoBlobsTablename),
				},
			},
		},
	})

	return err
}

func (dwr *DynamoDB) GetReferrersInfo(repo string, referredDigest godigest.Digest, artifactTypes []string,
) ([]mTypes.ReferrerInfo, error) {
	repoMeta, err := dwr.GetRepoMeta(context.Background(), repo)
	if err != nil {
		return []mTypes.ReferrerInfo{}, err
	}

	referrersInfo := repoMeta.Referrers[referredDigest.String()]

	filteredResults := make([]mTypes.ReferrerInfo, 0, len(referrersInfo))
	seenDigests := make(map[string]struct{})

	for _, referrerInfo := range referrersInfo {
		if !common.MatchesArtifactTypes(referrerInfo.ArtifactType, artifactTypes) {
			continue
		}

		if _, seen := seenDigests[referrerInfo.Digest]; seen {
			continue
		}

		seenDigests[referrerInfo.Digest] = struct{}{}

		filteredResults = append(filteredResults, referrerInfo)
	}

	return filteredResults, nil
}

func (dwr *DynamoDB) UpdateStatsOnDownload(repo string, reference string) error {
	repoMeta, err := dwr.getProtoRepoMeta(context.Background(), repo)
	if err != nil {
		return err
	}

	descriptorDigest := reference

	if !common.ReferenceIsDigest(reference) {
		// search digest for tag
		descriptor, found := repoMeta.Tags[reference]

		if !found {
			return zerr.ErrImageMetaNotFound
		}

		descriptorDigest = descriptor.Digest
	}

	manifestStatistics, ok := repoMeta.Statistics[descriptorDigest]
	if !ok {
		// Statistics entry doesn't exist - validate digest exists in this repository before creating it
		// Check if digest is referenced in any tag for this repository
		digestExists := false

		for _, tagDescriptor := range repoMeta.Tags {
			if tagDescriptor.Digest == descriptorDigest {
				digestExists = true

				break
			}
		}

		if !digestExists {
			return zerr.ErrImageMetaNotFound
		}

		// Statistics entry doesn't exist - create it
		// This can happen if SetRepoReference failed or wasn't called
		manifestStatistics = &proto_go.DescriptorStatistics{
			DownloadCount:     0,
			LastPullTimestamp: &timestamppb.Timestamp{},
			PushTimestamp:     &timestamppb.Timestamp{}, // Unknown push time
			PushedBy:          "",                       // Unknown pusher
		}
	}

	manifestStatistics.DownloadCount++
	manifestStatistics.LastPullTimestamp = timestamppb.Now()
	repoMeta.Statistics[descriptorDigest] = manifestStatistics

	return dwr.setProtoRepoMeta(repo, repoMeta)
}

func (dwr *DynamoDB) UpdateSignaturesValidity(ctx context.Context, repo string, manifestDigest godigest.Digest) error {
	imgTrustStore := dwr.ImageTrustStore()

	if imgTrustStore == nil {
		return nil
	}

	protoImageMeta, err := dwr.GetProtoImageMeta(ctx, manifestDigest)
	if err != nil {
		return err
	}

	// update signatures with details about validity and author
	protoRepoMeta, err := dwr.getProtoRepoMeta(ctx, repo)
	if err != nil {
		return err
	}

	manifestSignatures := proto_go.ManifestSignatures{Map: map[string]*proto_go.SignaturesInfo{"": {}}}

	for sigType, sigs := range protoRepoMeta.Signatures[manifestDigest.String()].Map {
		if zcommon.IsContextDone(ctx) {
			return ctx.Err()
		}

		signaturesInfo := []*proto_go.SignatureInfo{}

		for _, sigInfo := range sigs.List {
			layersInfo := []*proto_go.LayersInfo{}

			for _, layerInfo := range sigInfo.LayersInfo {
				author, date, isTrusted, _ := imgTrustStore.VerifySignature(sigType, layerInfo.LayerContent,
					layerInfo.SignatureKey, manifestDigest, mConvert.GetImageMeta(protoImageMeta), repo)

				if isTrusted {
					layerInfo.Signer = author
				}

				if !date.IsZero() {
					layerInfo.Signer = author
					layerInfo.Date = timestamppb.New(date)
				}

				layersInfo = append(layersInfo, layerInfo)
			}

			signaturesInfo = append(signaturesInfo, &proto_go.SignatureInfo{
				SignatureManifestDigest: sigInfo.SignatureManifestDigest,
				LayersInfo:              layersInfo,
			})
		}

		manifestSignatures.Map[sigType] = &proto_go.SignaturesInfo{List: signaturesInfo}
	}

	protoRepoMeta.Signatures[manifestDigest.String()] = &manifestSignatures

	return dwr.setProtoRepoMeta(protoRepoMeta.Name, protoRepoMeta) //nolint: contextcheck
}

func (dwr *DynamoDB) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
	sigMeta mTypes.SignatureMetadata,
) error {
	protoRepoMeta, err := dwr.getProtoRepoMeta(context.Background(), repo)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			protoRepoMeta = &proto_go.RepoMeta{
				Name:       repo,
				Tags:       map[string]*proto_go.TagDescriptor{"": {}},
				Statistics: map[string]*proto_go.DescriptorStatistics{"": {}},
				Referrers:  map[string]*proto_go.ReferrersInfo{"": {}},
				Signatures: map[string]*proto_go.ManifestSignatures{
					signedManifestDigest.String(): {
						Map: map[string]*proto_go.SignaturesInfo{
							sigMeta.SignatureType: {
								List: []*proto_go.SignatureInfo{
									{
										SignatureManifestDigest: sigMeta.SignatureDigest,
										LayersInfo:              mConvert.GetProtoLayersInfo(sigMeta.LayersInfo),
									},
								},
							},
						},
					},
				},
			}

			return dwr.setProtoRepoMeta(repo, protoRepoMeta)
		}

		return err
	}

	var (
		manifestSignatures *proto_go.ManifestSignatures
		found              bool
	)

	if manifestSignatures, found = protoRepoMeta.Signatures[signedManifestDigest.String()]; !found {
		manifestSignatures = &proto_go.ManifestSignatures{Map: map[string]*proto_go.SignaturesInfo{"": {}}}
	}

	signatureSlice := &proto_go.SignaturesInfo{List: []*proto_go.SignatureInfo{}}
	if sigSlice, found := manifestSignatures.Map[sigMeta.SignatureType]; found {
		signatureSlice = sigSlice
	}

	if !common.ProtoSignatureAlreadyExists(signatureSlice.List, sigMeta) {
		switch sigMeta.SignatureType {
		case zcommon.NotationSignature:
			signatureSlice.List = append(signatureSlice.List, &proto_go.SignatureInfo{
				SignatureManifestDigest: sigMeta.SignatureDigest,
				LayersInfo:              mConvert.GetProtoLayersInfo(sigMeta.LayersInfo),
			})
		case zcommon.CosignSignature:
			newCosignSig := &proto_go.SignatureInfo{
				SignatureManifestDigest: sigMeta.SignatureDigest,
				LayersInfo:              mConvert.GetProtoLayersInfo(sigMeta.LayersInfo),
			}

			if zcommon.IsCosignSignature(sigMeta.SignatureTag) {
				// the entry for "sha256-{digest}.sig" signatures should be overwritten if
				// it exists or added on the first position if it doesn't exist
				if len(signatureSlice.GetList()) == 0 {
					signatureSlice.List = []*proto_go.SignatureInfo{newCosignSig}
				} else {
					signatureSlice.List[0] = newCosignSig
				}
			} else {
				// the first position should be reserved for "sha256-{digest}.sig" signatures
				if len(signatureSlice.GetList()) == 0 {
					signatureSlice.List = []*proto_go.SignatureInfo{{
						SignatureManifestDigest: "",
						LayersInfo:              []*proto_go.LayersInfo{},
					}}
				}

				signatureSlice.List = append(signatureSlice.List, newCosignSig)
			}
		}
	}

	manifestSignatures.Map[sigMeta.SignatureType] = signatureSlice
	protoRepoMeta.Signatures[signedManifestDigest.String()] = manifestSignatures

	return dwr.setProtoRepoMeta(protoRepoMeta.Name, protoRepoMeta)
}

func (dwr *DynamoDB) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
	sigMeta mTypes.SignatureMetadata,
) error {
	protoRepoMeta, err := dwr.getProtoRepoMeta(context.Background(), repo)
	if err != nil {
		return err
	}

	sigType := sigMeta.SignatureType

	var (
		manifestSignatures *proto_go.ManifestSignatures
		found              bool
	)

	if manifestSignatures, found = protoRepoMeta.Signatures[signedManifestDigest.String()]; !found {
		return zerr.ErrImageMetaNotFound
	}

	signatureSlice := manifestSignatures.Map[sigType]

	newSignatureSlice := make([]*proto_go.SignatureInfo, 0, len(signatureSlice.List)-1)

	for _, sigDigest := range signatureSlice.List {
		if sigDigest.SignatureManifestDigest != sigMeta.SignatureDigest {
			newSignatureSlice = append(newSignatureSlice, sigDigest)
		}
	}

	manifestSignatures.Map[sigMeta.SignatureType] = &proto_go.SignaturesInfo{List: newSignatureSlice}

	protoRepoMeta.Signatures[signedManifestDigest.String()] = manifestSignatures

	return dwr.setProtoRepoMeta(protoRepoMeta.Name, protoRepoMeta)
}

func (dwr *DynamoDB) FilterImageMeta(ctx context.Context, digests []string,
) (map[string]mTypes.ImageMeta, error) {
	imageMetaAttributes, err := dwr.fetchImageMetaAttributesByDigest(ctx, digests)
	if err != nil {
		return nil, err
	}

	// Check if all requested digests were found
	// FilterImageMeta should return an error if any digest is missing (unlike getAllContainedMeta)
	if len(imageMetaAttributes) != len(digests) {
		// Build a map of found digests to identify which ones are missing
		foundDigests := make(map[string]bool)

		for _, attributes := range imageMetaAttributes {
			var digest string
			if err := attributevalue.Unmarshal(attributes["TableKey"], &digest); err == nil {
				foundDigests[digest] = true
			}
		}

		// Find the first missing digest
		for _, digest := range digests {
			if !foundDigests[digest] {
				return nil, fmt.Errorf("%w for digest %s", zerr.ErrImageMetaNotFound, digest)
			}
		}
	}

	results := map[string]mTypes.ImageMeta{}

	for _, attributes := range imageMetaAttributes {
		protoImageMeta, err := getProtoImageMetaFromAttribute(attributes["ImageMeta"])
		if err != nil {
			return nil, err
		}

		if protoImageMeta.MediaType == ispec.MediaTypeImageIndex ||
			compat.IsCompatibleManifestListMediaType(protoImageMeta.MediaType) {
			_, manifestDataList, err := dwr.getAllContainedMeta(context.Background(), protoImageMeta)
			if err != nil {
				return nil, err
			}

			protoImageMeta.Manifests = manifestDataList
		}

		results[mConvert.GetImageDigestStr(protoImageMeta)] = mConvert.GetImageMeta(protoImageMeta)
	}

	return results, nil
}

func (dwr *DynamoDB) RemoveRepoReference(repo, reference string, manifestDigest godigest.Digest,
) error {
	ctx := context.Background()

	protoRepoMeta, err := dwr.getProtoRepoMeta(context.Background(), repo)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return nil
		}

		return err
	}

	protoImageMeta, err := dwr.GetProtoImageMeta(context.TODO(), manifestDigest)
	if err != nil {
		if errors.Is(err, zerr.ErrImageMetaNotFound) {
			return nil
		}

		return err
	}

	// Remove Referrers
	if subject := mConvert.GetImageSubject(protoImageMeta); subject != nil {
		referredDigest := subject.Digest.String()
		refInfo := &proto_go.ReferrersInfo{}

		if protoRepoMeta.Referrers[referredDigest] != nil {
			refInfo = protoRepoMeta.Referrers[referredDigest]
		}

		referrers := refInfo.List

		for i := range referrers {
			if referrers[i].Digest == manifestDigest.String() {
				referrers[i].Count -= 1

				if referrers[i].Count == 0 || common.ReferenceIsDigest(reference) {
					referrers = append(referrers[:i], referrers[i+1:]...)
				}

				break
			}
		}

		refInfo.List = referrers

		protoRepoMeta.Referrers[referredDigest] = refInfo
	}

	if !common.ReferenceIsDigest(reference) {
		delete(protoRepoMeta.Tags, reference)
	} else {
		// find all tags pointing to this digest
		tags := []string{}

		for tag, desc := range protoRepoMeta.Tags {
			if desc.Digest == reference {
				tags = append(tags, tag)
			}
		}

		// remove all tags
		for _, tag := range tags {
			delete(protoRepoMeta.Tags, tag)
		}
	}

	/* try to find at least one tag pointing to manifestDigest
	if not found then we can also remove everything related to this digest */
	var foundTag bool

	for _, desc := range protoRepoMeta.Tags {
		if desc.Digest == manifestDigest.String() {
			foundTag = true
		}
	}

	if !foundTag {
		delete(protoRepoMeta.Statistics, manifestDigest.String())
		delete(protoRepoMeta.Signatures, manifestDigest.String())
		delete(protoRepoMeta.Referrers, manifestDigest.String())
	}

	repoBlobsInfo, err := dwr.getProtoRepoBlobs(ctx, repo)
	if err != nil {
		return err
	}

	protoRepoMeta, repoBlobsInfo = common.RemoveImageFromRepoMeta(protoRepoMeta, repoBlobsInfo, reference)

	err = dwr.setRepoBlobsInfo(repo, repoBlobsInfo) //nolint: contextcheck
	if err != nil {
		return err
	}

	err = dwr.setProtoRepoMeta(repo, protoRepoMeta) //nolint: contextcheck

	return err
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
	if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
		return res, err
	}

	if !slices.Contains(userData.BookmarkedRepos, repo) {
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

	if !slices.Contains(userData.StarredRepos, repo) {
		userData.StarredRepos = append(userData.StarredRepos, repo)
		res = mTypes.Added
	} else {
		userData.StarredRepos = zcommon.RemoveFrom(userData.StarredRepos, repo)
		res = mTypes.Removed
	}

	if res != mTypes.NotChanged {
		repoMeta, err := dwr.getProtoRepoMeta(ctx, repo) //nolint:contextcheck
		if err != nil {
			return mTypes.NotChanged, err
		}

		switch res {
		case mTypes.Added:
			repoMeta.Stars++
		case mTypes.Removed:
			repoMeta.Stars--
		}

		repoMetaBlob, err := proto.Marshal(repoMeta)
		if err != nil {
			return mTypes.NotChanged, err
		}

		repoAttributeValue, err := attributevalue.Marshal(repoMetaBlob)
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
							"TableKey": &types.AttributeValueMemberS{
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
							"#RM": "RepoMeta",
						},
						ExpressionAttributeValues: map[string]types.AttributeValue{
							":RepoMeta": repoAttributeValue,
						},
						Key: map[string]types.AttributeValue{
							"TableKey": &types.AttributeValueMemberS{
								Value: repo,
							},
						},
						TableName:        aws.String(dwr.RepoMetaTablename),
						UpdateExpression: aws.String("SET #RM = :RepoMeta"),
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

func (dwr DynamoDB) SetUserGroups(ctx context.Context, groups []string) error {
	userData, err := dwr.GetUserData(ctx)
	if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
		return err
	}

	userData.Groups = groups

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
		return nil, fmt.Errorf("failed to get userData for identity %s %w", userid, err)
	}

	changed := false

	for hashedKey, apiKeyDetails := range userData.APIKeys {
		// if expiresAt is not nil value
		if !apiKeyDetails.ExpirationDate.Equal(time.Time{}) && time.Now().After(apiKeyDetails.ExpirationDate) {
			apiKeyDetails.IsExpired = true

			changed = true
		}

		userData.APIKeys[hashedKey] = apiKeyDetails

		apiKeys = append(apiKeys, apiKeyDetails)
	}

	if !changed {
		// return early, no need to make a call to update key expiry in the DB
		return apiKeys, nil
	}

	err = dwr.SetUserData(ctx, userData)

	return apiKeys, err
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
		return fmt.Errorf("failed to get userData for identity %s %w", userid, err)
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
						"TableKey": &types.AttributeValueMemberS{
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
						"TableKey": &types.AttributeValueMemberS{
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
		return fmt.Errorf("failed to get userData %w", err)
	}

	for hash, apiKeyDetails := range userData.APIKeys {
		if apiKeyDetails.UUID == keyID {
			delete(userData.APIKeys, hash)

			_, err = dwr.Client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
				TableName: aws.String(dwr.APIKeyTablename),
				Key: map[string]types.AttributeValue{
					"TableKey": &types.AttributeValueMemberS{Value: hash},
				},
			})
			if err != nil {
				return fmt.Errorf("failed to delete userAPIKey entry for hash %s %w", hash, err)
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
			"TableKey": &types.AttributeValueMemberS{Value: hashedKey},
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
			"TableKey": &types.AttributeValueMemberS{Value: userid},
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
			"TableKey": &types.AttributeValueMemberS{
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
			"TableKey": &types.AttributeValueMemberS{Value: userid},
		},
	})

	return err
}

const AwsS3BatchLimit = 100

func (dwr *DynamoDB) fetchImageMetaAttributesByDigest(ctx context.Context, digests []string,
) ([]map[string]types.AttributeValue, error) {
	// AWS S3 as a limit (=100) on number of keys that can retrieved in one
	// request, so break it up
	batchedResp := []map[string]types.AttributeValue{}

	for start := 0; start < len(digests); {
		size := min(len(digests)-start, AwsS3BatchLimit)
		end := start + size

		resp, err := dwr.Client.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
			RequestItems: map[string]types.KeysAndAttributes{
				dwr.ImageMetaTablename: {
					Keys: getBatchImageKeys(digests[start:end]),
				},
			},
		})
		if err != nil {
			return nil, err
		}

		// Missing manifests are allowed - append whatever was found
		batchedResp = append(batchedResp, resp.Responses[dwr.ImageMetaTablename]...)
		start = end
	}

	// Order the responses based on initial digest order
	// as BatchGetItem does not guarantee the key order is respected
	orderedResp := []map[string]types.AttributeValue{}
	respMap := map[string]map[string]types.AttributeValue{}

	for _, item := range batchedResp {
		var digest string

		err := attributevalue.Unmarshal(item["TableKey"], &digest)
		if err != nil {
			return nil, err
		}

		respMap[digest] = item
	}

	// Only include digests that were actually found (missing ones are skipped gracefully)
	for _, digest := range digests {
		imageMeta, ok := respMap[digest]
		if ok {
			orderedResp = append(orderedResp, imageMeta)
		}
	}

	return orderedResp, nil
}

func getBatchImageKeys(digests []string) []map[string]types.AttributeValue {
	result := []map[string]types.AttributeValue{}

	for _, digest := range digests {
		result = append(result, map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{
				Value: digest,
			},
		})
	}

	return result
}

func (dwr *DynamoDB) PatchDB() error {
	DBVersion, err := dwr.getDBVersion()
	if err != nil {
		return fmt.Errorf("patching dynamo failed, error retrieving database version %w", err)
	}

	if version.GetVersionIndex(DBVersion) == -1 {
		return fmt.Errorf("%w: %s could not identify patches", zerr.ErrInvalidMetaDBVersion, DBVersion)
	}

	for patchIndex, patch := range dwr.Patches {
		if patchIndex < version.GetVersionIndex(DBVersion) {
			continue
		}

		tableNames := map[string]string{
			"RepoMetaTablename": dwr.RepoMetaTablename,
			"VersionTablename":  dwr.VersionTablename,
		}

		err := patch(dwr.Client, tableNames)
		if err != nil {
			return err
		}
	}

	return nil
}

func (dwr *DynamoDB) ResetDB() error {
	err := dwr.ResetTable(dwr.APIKeyTablename)
	if err != nil {
		return err
	}

	err = dwr.ResetTable(dwr.ImageMetaTablename)
	if err != nil {
		return err
	}

	err = dwr.ResetTable(dwr.RepoBlobsTablename)
	if err != nil {
		return err
	}

	err = dwr.ResetTable(dwr.RepoMetaTablename)
	if err != nil {
		return err
	}

	err = dwr.ResetTable(dwr.UserDataTablename)
	if err != nil {
		return err
	}

	return nil
}

func (dwr *DynamoDB) ResetTable(tableName string) error {
	err := dwr.deleteTable(tableName)
	if err != nil {
		return err
	}

	return dwr.createTable(tableName)
}

func (dwr *DynamoDB) createTable(tableName string) error {
	_, err := dwr.Client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("TableKey"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("TableKey"),
				KeyType:       types.KeyTypeHash,
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})
	if err != nil {
		inUseException := new(types.ResourceInUseException)
		if !errors.As(err, &inUseException) {
			return err
		}
	}

	return dwr.waitTableToBeCreated(tableName)
}

func (dwr *DynamoDB) deleteTable(tableName string) error {
	_, err := dwr.Client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
		TableName: aws.String(tableName),
	})

	if temp := new(types.ResourceNotFoundException); errors.As(err, &temp) {
		return nil
	}

	return dwr.waitTableToBeDeleted(tableName)
}

func (dwr *DynamoDB) waitTableToBeCreated(tableName string) error {
	const maxWaitTime = 120 * time.Second

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

func (dwr *DynamoDB) createVersionTable() error {
	_, err := dwr.Client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String(dwr.VersionTablename),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("TableKey"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("TableKey"),
				KeyType:       types.KeyTypeHash,
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})
	if err != nil {
		inUseException := new(types.ResourceInUseException)
		if !errors.As(err, &inUseException) {
			return err
		}
		// Table already exists, continue to ensure version data is set
	}

	err = dwr.waitTableToBeCreated(dwr.VersionTablename)
	if err != nil {
		return err
	}

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
			"TableKey": &types.AttributeValueMemberS{
				Value: version.DBVersionKey,
			},
		},
		TableName:           aws.String(dwr.VersionTablename),
		UpdateExpression:    aws.String("SET #V = :Version"),
		ConditionExpression: aws.String("attribute_not_exists(#V)"),
	})
	if err != nil {
		conditionalCheckFailedException := new(types.ConditionalCheckFailedException)
		if errors.As(err, &conditionalCheckFailedException) {
			// Version already exists, skip setting it - patches will handle version updates
			return nil
		}

		return err
	}

	return nil
}

func (dwr *DynamoDB) getDBVersion() (string, error) {
	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.VersionTablename),
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{Value: version.DBVersionKey},
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

func (dwr *DynamoDB) Close() error {
	return nil
}
