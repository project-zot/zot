package convert

import (
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"zotregistry.dev/zot/v2/pkg/common"
	proto_go "zotregistry.dev/zot/v2/pkg/meta/proto/gen"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
)

func GetProtoRepoMeta(repo mTypes.RepoMeta) *proto_go.RepoMeta {
	return &proto_go.RepoMeta{
		Name:             repo.Name,
		Tags:             GetProtoTags(repo.Tags),
		Statistics:       GetProtoStatistics(repo.Statistics),
		Signatures:       GetProtoSignatures(repo.Signatures),
		Referrers:        GetProtoReferrers(repo.Referrers),
		Size:             repo.Size,
		Vendors:          repo.Vendors,
		Platforms:        GetProtoPlatforms(repo.Platforms),
		LastUpdatedImage: GetProtoLastUpdatedImage(repo.LastUpdatedImage),
		Stars:            int32(repo.StarCount),     //nolint:gosec // ignore overflow
		Downloads:        int32(repo.DownloadCount), //nolint:gosec // ignore overflow
	}
}

func GetProtoImageMeta(imageMeta mTypes.ImageMeta) *proto_go.ImageMeta {
	switch imageMeta.MediaType {
	case ispec.MediaTypeImageManifest:
		if len(imageMeta.Manifests) == 0 {
			return nil
		}

		manifestData := imageMeta.Manifests[0]

		return GetProtoImageManifestData(manifestData.Manifest, manifestData.Config, manifestData.Size,
			manifestData.Digest.String())
	case ispec.MediaTypeImageIndex:
		if imageMeta.Index == nil {
			return nil
		}

		return GetProtoImageIndexMeta(*imageMeta.Index, imageMeta.Size, imageMeta.Digest.String())
	default:
		return nil
	}
}

func GetProtoImageManifestData(manifestContent ispec.Manifest, configContent ispec.Image, size int64, digest string,
) *proto_go.ImageMeta {
	return &proto_go.ImageMeta{
		MediaType: ispec.MediaTypeImageManifest,
		Manifests: []*proto_go.ManifestMeta{GetProtoManifestMeta(manifestContent, configContent, size, digest)},
		Index:     nil,
	}
}

func GetProtoManifestMeta(manifestContent ispec.Manifest, configContent ispec.Image, size int64, digest string,
) *proto_go.ManifestMeta {
	return &proto_go.ManifestMeta{
		Digest: digest,
		Size:   size,
		Manifest: &proto_go.Manifest{
			Versioned: &proto_go.Versioned{SchemaVersion: int32(manifestContent.SchemaVersion)}, //nolint:gosec,lll // ignore overflow
			Config: &proto_go.Descriptor{
				Digest:    manifestContent.Config.Digest.String(),
				Size:      manifestContent.Config.Size,
				MediaType: manifestContent.Config.MediaType,
			},
			MediaType:    ref(ispec.MediaTypeImageManifest),
			ArtifactType: &manifestContent.ArtifactType,
			Layers:       getProtoManifestLayers(manifestContent.Layers),
			Subject:      getProtoDesc(manifestContent.Subject),
			Annotations:  manifestContent.Annotations,
		},
		Config: &proto_go.Image{
			Created:  GetProtoTime(configContent.Created),
			Author:   &configContent.Author,
			Platform: GetProtoPlatform(&configContent.Platform),
			Config: &proto_go.ImageConfig{
				User:         configContent.Config.User,
				ExposedPorts: getProtoExposedPorts(configContent.Config.ExposedPorts),
				Env:          configContent.Config.Env,
				Entrypoint:   configContent.Config.Entrypoint,
				Cmd:          configContent.Config.Cmd,
				Volumes:      getProtoConfigVolumes(configContent.Config.Volumes),
				WorkingDir:   &configContent.Config.WorkingDir,
				Labels:       configContent.Config.Labels,
				StopSignal:   &configContent.Config.StopSignal,
			},
			RootFS: &proto_go.RootFS{
				Type:    configContent.RootFS.Type,
				DiffIDs: getProtoDiffIDs(configContent.RootFS.DiffIDs),
			},
			History: getProtoHistory(configContent.History),
		},
	}
}

func GetProtoImageIndexMeta(indexContent ispec.Index, size int64, digest string) *proto_go.ImageMeta {
	return &proto_go.ImageMeta{
		MediaType: ispec.MediaTypeImageIndex,
		Index: &proto_go.IndexMeta{
			Size:   size,
			Digest: digest,
			Index: &proto_go.Index{
				Versioned:    &proto_go.Versioned{SchemaVersion: int32(indexContent.Versioned.SchemaVersion)}, //nolint:gosec,lll // ignore overflow
				MediaType:    ref(ispec.MediaTypeImageIndex),
				ArtifactType: ref(common.GetIndexArtifactType(indexContent)),
				Manifests:    getProtoManifestList(indexContent.Manifests),
				Subject:      getProtoDesc(indexContent.Subject),
				Annotations:  indexContent.Annotations,
			},
		},
	}
}

func GetProtoStatistics(stats map[mTypes.ImageDigest]mTypes.DescriptorStatistics,
) map[mTypes.ImageDigest]*proto_go.DescriptorStatistics {
	results := map[mTypes.ImageDigest]*proto_go.DescriptorStatistics{}

	for digest, stat := range stats {
		results[digest] = &proto_go.DescriptorStatistics{
			DownloadCount:     int32(stat.DownloadCount), //nolint:gosec // ignore overflow
			LastPullTimestamp: timestamppb.New(stat.LastPullTimestamp),
			PushTimestamp:     timestamppb.New(stat.PushTimestamp),
			PushedBy:          stat.PushedBy,
		}
	}

	return results
}

func GetProtoPlatforms(platforms []ispec.Platform) []*proto_go.Platform {
	result := []*proto_go.Platform{}

	for i := range platforms {
		result = append(result, &proto_go.Platform{
			OS:           platforms[i].OS,
			Architecture: platforms[i].Architecture,
		})
	}

	return result
}

func GetProtoReferrers(refs map[string][]mTypes.ReferrerInfo) map[string]*proto_go.ReferrersInfo {
	results := map[string]*proto_go.ReferrersInfo{}

	for digest, ref := range refs {
		referrersInfoList := []*proto_go.ReferrerInfo{}

		for _, dbRef := range ref {
			referrersInfoList = append(referrersInfoList, GetProtoReferrerInfo(dbRef))
		}

		results[digest] = &proto_go.ReferrersInfo{List: referrersInfoList}
	}

	return results
}

func GetProtoSignatures(sigs map[string]mTypes.ManifestSignatures) map[string]*proto_go.ManifestSignatures {
	results := map[string]*proto_go.ManifestSignatures{}

	for digest, dbSignatures := range sigs {
		imageSignatures := &proto_go.ManifestSignatures{Map: map[string]*proto_go.SignaturesInfo{}}

		for signatureName, signatureInfo := range dbSignatures {
			imageSignatures.Map[signatureName] = &proto_go.SignaturesInfo{List: GetProtoSignaturesInfo(signatureInfo)}
		}

		results[digest] = imageSignatures
	}

	return results
}

func GetProtoSignaturesInfo(sigsInfo []mTypes.SignatureInfo) []*proto_go.SignatureInfo {
	results := []*proto_go.SignatureInfo{}

	for _, sigInfo := range sigsInfo {
		results = append(results, &proto_go.SignatureInfo{
			SignatureManifestDigest: sigInfo.SignatureManifestDigest,
			LayersInfo:              GetProtoLayersInfo(sigInfo.LayersInfo),
		})
	}

	return results
}

func GetProtoLayersInfo(layersInfo []mTypes.LayerInfo) []*proto_go.LayersInfo {
	result := make([]*proto_go.LayersInfo, 0, len(layersInfo))

	for _, layerInfo := range layersInfo {
		result = append(result, &proto_go.LayersInfo{
			LayerDigest:  layerInfo.LayerDigest,
			LayerContent: layerInfo.LayerContent,
			SignatureKey: layerInfo.SignatureKey,
			Signer:       layerInfo.Signer,
			Date:         timestamppb.New(layerInfo.Date),
		})
	}

	return result
}

func getProtoManifestLayers(layers []ispec.Descriptor) []*proto_go.Descriptor {
	protoLayers := []*proto_go.Descriptor{}

	for _, layer := range layers {
		protoLayers = append(protoLayers, getProtoDesc(&layer))
	}

	return protoLayers
}

func getProtoDesc(descriptor *ispec.Descriptor) *proto_go.Descriptor {
	if descriptor == nil {
		return nil
	}

	return &proto_go.Descriptor{
		MediaType:    descriptor.MediaType,
		Digest:       descriptor.Digest.String(),
		Size:         descriptor.Size,
		URLs:         descriptor.URLs,
		Annotations:  descriptor.Annotations,
		Data:         descriptor.Data,
		Platform:     GetProtoPlatform(descriptor.Platform),
		ArtifactType: &descriptor.ArtifactType,
	}
}

func getProtoManifestList(manifests []ispec.Descriptor) []*proto_go.Descriptor {
	result := make([]*proto_go.Descriptor, 0, len(manifests))

	for _, manifest := range manifests {
		result = append(result, &proto_go.Descriptor{
			MediaType:    manifest.MediaType,
			Digest:       manifest.Digest.String(),
			Size:         manifest.Size,
			URLs:         manifest.URLs,
			Annotations:  manifest.Annotations,
			Data:         manifest.Data,
			Platform:     GetProtoPlatform(manifest.Platform),
			ArtifactType: ref(manifest.ArtifactType),
		})
	}

	return result
}

func GetProtoPlatform(platform *ispec.Platform) *proto_go.Platform {
	if platform == nil {
		return nil
	}

	return &proto_go.Platform{
		Architecture: platform.Architecture,
		OS:           platform.OS,
		OSVersion:    ref(platform.OSVersion),
		OSFeatures:   platform.OSFeatures,
		Variant:      ref(platform.Variant),
	}
}

func getProtoHistory(historySlice []ispec.History) []*proto_go.History {
	protoHistory := []*proto_go.History{}

	for _, history := range historySlice {
		protoHistory = append(protoHistory, &proto_go.History{
			Created:    GetProtoTime(history.Created),
			CreatedBy:  &history.CreatedBy,
			Author:     &history.Author,
			Comment:    &history.Comment,
			EmptyLayer: &history.EmptyLayer,
		})
	}

	return protoHistory
}

func getProtoDiffIDs(digests []godigest.Digest) []string {
	digestsStr := []string{}

	for _, digest := range digests {
		digestsStr = append(digestsStr, digest.String())
	}

	return digestsStr
}

func getProtoExposedPorts(exposedPorts map[string]struct{}) map[string]*proto_go.EmptyMessage {
	protoPorts := map[string]*proto_go.EmptyMessage{}

	for i := range exposedPorts {
		protoPorts[i] = &proto_go.EmptyMessage{}
	}

	return protoPorts
}

func getProtoConfigVolumes(volumes map[string]struct{}) map[string]*proto_go.EmptyMessage {
	protoVolumes := map[string]*proto_go.EmptyMessage{}

	for i := range volumes {
		protoVolumes[i] = &proto_go.EmptyMessage{}
	}

	return protoVolumes
}

func GetProtoReferrerInfo(referrer mTypes.ReferrerInfo) *proto_go.ReferrerInfo {
	return &proto_go.ReferrerInfo{
		Digest:       referrer.Digest,
		MediaType:    referrer.MediaType,
		ArtifactType: referrer.ArtifactType,
		Size:         int64(referrer.Size),
		Annotations:  referrer.Annotations,
	}
}

func GetProtoTime(time *time.Time) *timestamppb.Timestamp {
	if time == nil {
		return nil
	}

	return timestamppb.New(*time)
}

func GetProtoTags(tags map[mTypes.Tag]mTypes.Descriptor) map[mTypes.Tag]*proto_go.TagDescriptor {
	resultMap := map[mTypes.Tag]*proto_go.TagDescriptor{}

	for tag, tagDescriptor := range tags {
		protoTagDescriptor := &proto_go.TagDescriptor{
			Digest:    tagDescriptor.Digest,
			MediaType: tagDescriptor.MediaType,
		}
		if !tagDescriptor.TaggedTimestamp.IsZero() {
			protoTagDescriptor.TaggedTimestamp = timestamppb.New(tagDescriptor.TaggedTimestamp)
		}
		resultMap[tag] = protoTagDescriptor
	}

	return resultMap
}

func GetProtoLastUpdatedImage(lastUpdatedImage *mTypes.LastUpdatedImage) *proto_go.RepoLastUpdatedImage {
	if lastUpdatedImage == nil {
		return nil
	}

	return &proto_go.RepoLastUpdatedImage{
		LastUpdated: GetProtoTime(lastUpdatedImage.LastUpdated),
		MediaType:   lastUpdatedImage.MediaType,
		Digest:      lastUpdatedImage.Digest,
		Tag:         lastUpdatedImage.Tag,
	}
}

func GetProtoEarlierUpdatedImage(repoLastImage *proto_go.RepoLastUpdatedImage, lastImage *proto_go.RepoLastUpdatedImage,
) *proto_go.RepoLastUpdatedImage {
	if repoLastImage == nil {
		return lastImage
	}

	if lastImage == nil || lastImage.LastUpdated == nil {
		return repoLastImage
	}

	if repoLastImage.LastUpdated == nil {
		return lastImage
	}

	if repoLastImage.LastUpdated.AsTime().Before(lastImage.LastUpdated.AsTime()) {
		return lastImage
	}

	return repoLastImage
}

func ref[T any](input T) *T {
	ref := input

	return &ref
}
