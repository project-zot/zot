package convert

import (
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"zotregistry.dev/zot/pkg/common"
	proto_go "zotregistry.dev/zot/pkg/meta/proto/gen"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
)

func GetHistory(history []*proto_go.History) []ispec.History {
	if history == nil {
		return nil
	}

	results := make([]ispec.History, 0, len(history))

	for _, his := range history {
		results = append(results, ispec.History{
			Created:    ref(his.Created.AsTime()),
			CreatedBy:  deref(his.CreatedBy, ""),
			Author:     deref(his.Author, ""),
			Comment:    deref(his.Comment, ""),
			EmptyLayer: deref(his.EmptyLayer, false),
		})
	}

	return results
}

func GetImageArtifactType(imageMeta *proto_go.ImageMeta) string {
	switch imageMeta.MediaType {
	case ispec.MediaTypeImageManifest:
		manifestArtifactType := deref(imageMeta.Manifests[0].Manifest.ArtifactType, "")
		if manifestArtifactType != "" {
			return manifestArtifactType
		}

		return imageMeta.Manifests[0].Manifest.Config.MediaType
	case ispec.MediaTypeImageIndex:
		return deref(imageMeta.Index.Index.ArtifactType, "")
	default:
		return ""
	}
}

func GetImageManifestSize(imageMeta *proto_go.ImageMeta) int64 {
	switch imageMeta.MediaType {
	case ispec.MediaTypeImageManifest:
		return imageMeta.Manifests[0].Size
	case ispec.MediaTypeImageIndex:
		return imageMeta.Index.Size
	default:
		return 0
	}
}

func GetImageDigest(imageMeta *proto_go.ImageMeta) godigest.Digest {
	switch imageMeta.MediaType {
	case ispec.MediaTypeImageManifest:
		return godigest.Digest(imageMeta.Manifests[0].Digest)
	case ispec.MediaTypeImageIndex:
		return godigest.Digest(imageMeta.Index.Digest)
	default:
		return ""
	}
}

func GetImageDigestStr(imageMeta *proto_go.ImageMeta) string {
	switch imageMeta.MediaType {
	case ispec.MediaTypeImageManifest:
		return imageMeta.Manifests[0].Digest
	case ispec.MediaTypeImageIndex:
		return imageMeta.Index.Digest
	default:
		return ""
	}
}

func GetImageAnnotations(imageMeta *proto_go.ImageMeta) map[string]string {
	switch imageMeta.MediaType {
	case ispec.MediaTypeImageManifest:
		return imageMeta.Manifests[0].Manifest.Annotations
	case ispec.MediaTypeImageIndex:
		return imageMeta.Index.Index.Annotations
	default:
		return map[string]string{}
	}
}

func GetImageSubject(imageMeta *proto_go.ImageMeta) *ispec.Descriptor {
	switch imageMeta.MediaType {
	case ispec.MediaTypeImageManifest:
		if imageMeta.Manifests[0].Manifest.Subject == nil {
			return nil
		}

		return GetDescriptorRef(imageMeta.Manifests[0].Manifest.Subject)
	case ispec.MediaTypeImageIndex:
		if imageMeta.Index.Index.Subject == nil {
			return nil
		}

		return GetDescriptorRef(imageMeta.Index.Index.Subject)
	default:
		return nil
	}
}

func GetDescriptorRef(descriptor *proto_go.Descriptor) *ispec.Descriptor {
	if descriptor == nil {
		return nil
	}

	platform := GetPlatformRef(descriptor.Platform)

	return &ispec.Descriptor{
		MediaType:    descriptor.MediaType,
		Digest:       godigest.Digest(descriptor.Digest),
		Size:         descriptor.Size,
		URLs:         descriptor.URLs,
		Data:         descriptor.Data,
		Platform:     platform,
		ArtifactType: deref(descriptor.ArtifactType, ""),
		Annotations:  descriptor.Annotations,
	}
}

func GetPlatform(platform *proto_go.Platform) ispec.Platform {
	if platform == nil {
		return ispec.Platform{}
	}

	return ispec.Platform{
		Architecture: platform.Architecture,
		OS:           platform.OS,
		OSVersion:    deref(platform.OSVersion, ""),
		OSFeatures:   platform.OSFeatures,
		Variant:      deref(platform.Variant, ""),
	}
}

func GetPlatformRef(platform *proto_go.Platform) *ispec.Platform {
	if platform == nil {
		return nil
	}

	return &ispec.Platform{
		Architecture: platform.Architecture,
		OS:           platform.OS,
		OSVersion:    deref(platform.OSVersion, ""),
		OSFeatures:   platform.OSFeatures,
		Variant:      deref(platform.Variant, ""),
	}
}

func GetLayers(descriptors []*proto_go.Descriptor) []ispec.Descriptor {
	results := make([]ispec.Descriptor, 0, len(descriptors))

	for _, desc := range descriptors {
		results = append(results, ispec.Descriptor{
			MediaType: desc.MediaType,
			Digest:    godigest.Digest(desc.Digest),
			Size:      desc.Size,
		})
	}

	return results
}

func GetSubject(subj *proto_go.Descriptor) *ispec.Descriptor {
	if subj == nil {
		return nil
	}

	return &ispec.Descriptor{
		MediaType: subj.MediaType,
		Digest:    godigest.Digest(subj.Digest),
		Size:      subj.Size,
	}
}

func GetReferrers(refs map[string]*proto_go.ReferrersInfo) map[string][]mTypes.ReferrerInfo {
	results := map[string][]mTypes.ReferrerInfo{}

	for digest, ref := range refs {
		referrers := []mTypes.ReferrerInfo{}

		for _, dbRef := range ref.List {
			referrers = append(referrers, mTypes.ReferrerInfo{
				Digest:       dbRef.Digest,
				MediaType:    dbRef.MediaType,
				ArtifactType: dbRef.ArtifactType,
				Size:         int(dbRef.Size),
				Annotations:  dbRef.Annotations,
			})
		}

		results[digest] = referrers
	}

	return results
}

func GetImageReferrers(refs *proto_go.ReferrersInfo) []mTypes.ReferrerInfo {
	if refs == nil {
		return []mTypes.ReferrerInfo{}
	}

	results := []mTypes.ReferrerInfo{}

	for _, dbRef := range refs.List {
		results = append(results, mTypes.ReferrerInfo{
			Digest:       dbRef.Digest,
			MediaType:    dbRef.MediaType,
			ArtifactType: dbRef.ArtifactType,
			Size:         int(dbRef.Size),
			Annotations:  dbRef.Annotations,
		})
	}

	return results
}

func GetSignatures(sigs map[string]*proto_go.ManifestSignatures) map[string]mTypes.ManifestSignatures {
	results := map[string]mTypes.ManifestSignatures{}

	for digest, dbSignatures := range sigs {
		imageSignatures := mTypes.ManifestSignatures{}

		for signatureName, signatureInfo := range dbSignatures.Map {
			imageSignatures[signatureName] = GetSignaturesInfo(signatureInfo.List)
		}

		results[digest] = imageSignatures
	}

	return results
}

func GetImageSignatures(sigs *proto_go.ManifestSignatures) mTypes.ManifestSignatures {
	if sigs == nil {
		return mTypes.ManifestSignatures{}
	}

	results := mTypes.ManifestSignatures{}

	for signatureName, signatureInfo := range sigs.Map {
		results[signatureName] = GetSignaturesInfo(signatureInfo.List)
	}

	return results
}

func GetSignaturesInfo(sigsInfo []*proto_go.SignatureInfo) []mTypes.SignatureInfo {
	results := []mTypes.SignatureInfo{}

	for _, siginfo := range sigsInfo {
		results = append(results, mTypes.SignatureInfo{
			SignatureManifestDigest: siginfo.SignatureManifestDigest,
			LayersInfo:              GetLayersInfo(siginfo.LayersInfo),
		})
	}

	return results
}

func GetLayersInfo(layersInfo []*proto_go.LayersInfo) []mTypes.LayerInfo {
	results := []mTypes.LayerInfo{}

	for _, layerInfo := range layersInfo {
		date := time.Time{}

		if layerInfo.Date != nil {
			date = layerInfo.Date.AsTime()
		}

		results = append(results, mTypes.LayerInfo{
			LayerDigest:  layerInfo.LayerDigest,
			LayerContent: layerInfo.LayerContent,
			SignatureKey: layerInfo.SignatureKey,
			Signer:       layerInfo.Signer,
			Date:         date,
		})
	}

	return results
}

func GetStatisticsMap(stats map[mTypes.ImageDigest]*proto_go.DescriptorStatistics,
) map[mTypes.ImageDigest]mTypes.DescriptorStatistics {
	results := map[mTypes.ImageDigest]mTypes.DescriptorStatistics{}

	for digest, stat := range stats {
		results[digest] = mTypes.DescriptorStatistics{
			DownloadCount:     int(stat.DownloadCount),
			LastPullTimestamp: stat.LastPullTimestamp.AsTime(),
			PushTimestamp:     stat.PushTimestamp.AsTime(),
			PushedBy:          stat.PushedBy,
		}
	}

	return results
}

func GetImageStatistics(stats *proto_go.DescriptorStatistics) mTypes.DescriptorStatistics {
	if stats == nil {
		return mTypes.DescriptorStatistics{}
	}

	return mTypes.DescriptorStatistics{
		DownloadCount:     int(stats.DownloadCount),
		LastPullTimestamp: stats.LastPullTimestamp.AsTime(),
		PushTimestamp:     stats.PushTimestamp.AsTime(),
		PushedBy:          stats.PushedBy,
	}
}

func GetImageManifestMeta(manifestContent ispec.Manifest, configContent ispec.Image, size int64,
	digest godigest.Digest,
) mTypes.ImageMeta {
	return mTypes.ImageMeta{
		MediaType: ispec.MediaTypeImageManifest,
		Digest:    digest,
		Size:      size,
		Manifests: []mTypes.ManifestMeta{
			{
				Digest:   digest,
				Size:     size,
				Config:   configContent,
				Manifest: manifestContent,
			},
		},
	}
}

func GetImageIndexMeta(indexContent ispec.Index, size int64, digest godigest.Digest) mTypes.ImageMeta {
	return mTypes.ImageMeta{
		MediaType: ispec.MediaTypeImageIndex,
		Index:     &indexContent,
		Manifests: GetManifests(indexContent.Manifests),
		Size:      size,
		Digest:    digest,
	}
}

func GetTags(tags map[mTypes.Tag]*proto_go.TagDescriptor) map[mTypes.Tag]mTypes.Descriptor {
	resultMap := map[mTypes.Tag]mTypes.Descriptor{}

	for tag, tagDescriptor := range tags {
		resultMap[tag] = mTypes.Descriptor{
			Digest:    tagDescriptor.Digest,
			MediaType: tagDescriptor.MediaType,
		}
	}

	return resultMap
}

func GetManifests(descriptors []ispec.Descriptor) []mTypes.ManifestMeta {
	manifestList := []mTypes.ManifestMeta{}

	for _, manifest := range descriptors {
		manifestList = append(manifestList, mTypes.ManifestMeta{
			Digest: manifest.Digest,
			Size:   manifest.Size,
		})
	}

	return manifestList
}

func GetTime(time *timestamppb.Timestamp) *time.Time {
	if time == nil {
		return nil
	}

	return ref(time.AsTime())
}

func GetFullImageMetaFromProto(tag string, protoRepoMeta *proto_go.RepoMeta, protoImageMeta *proto_go.ImageMeta,
) mTypes.FullImageMeta {
	if protoRepoMeta == nil {
		return mTypes.FullImageMeta{}
	}

	imageMeta := GetImageMeta(protoImageMeta)
	imageDigest := imageMeta.Digest.String()

	return mTypes.FullImageMeta{
		Repo:         protoRepoMeta.Name,
		Tag:          tag,
		MediaType:    imageMeta.MediaType,
		Digest:       imageMeta.Digest,
		Size:         imageMeta.Size,
		Index:        imageMeta.Index,
		Manifests:    GetFullManifestData(protoRepoMeta, imageMeta.Manifests),
		IsStarred:    protoRepoMeta.IsStarred,
		IsBookmarked: protoRepoMeta.IsBookmarked,

		Referrers:  GetImageReferrers(protoRepoMeta.Referrers[imageDigest]),
		Statistics: GetImageStatistics(protoRepoMeta.Statistics[imageDigest]),
		Signatures: GetImageSignatures(protoRepoMeta.Signatures[imageDigest]),
	}
}

func GetFullManifestData(protoRepoMeta *proto_go.RepoMeta, manifestData []mTypes.ManifestMeta,
) []mTypes.FullManifestMeta {
	if protoRepoMeta == nil {
		return []mTypes.FullManifestMeta{}
	}

	results := []mTypes.FullManifestMeta{}

	for i := range manifestData {
		results = append(results, mTypes.FullManifestMeta{
			ManifestMeta: manifestData[i],
			Referrers:    GetImageReferrers(protoRepoMeta.Referrers[manifestData[i].Digest.String()]),
			Statistics:   GetImageStatistics(protoRepoMeta.Statistics[manifestData[i].Digest.String()]),
			Signatures:   GetImageSignatures(protoRepoMeta.Signatures[manifestData[i].Digest.String()]),
		})
	}

	return results
}

func GetRepoMeta(protoRepoMeta *proto_go.RepoMeta) mTypes.RepoMeta {
	if protoRepoMeta == nil {
		return mTypes.RepoMeta{}
	}

	repoDownloads := int32(0)

	for _, descriptor := range protoRepoMeta.Tags {
		if statistic := protoRepoMeta.Statistics[descriptor.Digest]; statistic != nil {
			repoDownloads += statistic.DownloadCount
		}
	}

	return mTypes.RepoMeta{
		Name:             protoRepoMeta.Name,
		Tags:             GetTags(protoRepoMeta.Tags),
		Rank:             int(protoRepoMeta.Rank),
		Size:             protoRepoMeta.Size,
		Platforms:        GetPlatforms(protoRepoMeta.Platforms),
		Vendors:          protoRepoMeta.Vendors,
		IsStarred:        protoRepoMeta.IsStarred,
		IsBookmarked:     protoRepoMeta.IsBookmarked,
		StarCount:        int(protoRepoMeta.Stars),
		DownloadCount:    int(repoDownloads),
		LastUpdatedImage: GetLastUpdatedImage(protoRepoMeta.LastUpdatedImage),
		Statistics:       GetStatisticsMap(protoRepoMeta.Statistics),
		Signatures:       GetSignatures(protoRepoMeta.Signatures),
		Referrers:        GetReferrers(protoRepoMeta.Referrers),
	}
}

func GetPlatforms(platforms []*proto_go.Platform) []ispec.Platform {
	result := []ispec.Platform{}

	for i := range platforms {
		result = append(result, GetPlatform(platforms[i]))
	}

	return result
}

func AddProtoPlatforms(platforms []*proto_go.Platform, newPlatforms []*proto_go.Platform) []*proto_go.Platform {
	for _, newPlatform := range newPlatforms {
		if !ContainsProtoPlatform(platforms, newPlatform) {
			platforms = append(platforms, newPlatform)
		}
	}

	return platforms
}

func ContainsProtoPlatform(platforms []*proto_go.Platform, platform *proto_go.Platform) bool {
	for i := range platforms {
		if platforms[i].OS == platform.OS && platforms[i].Architecture == platform.Architecture {
			return true
		}
	}

	return false
}

func AddVendors(vendors []string, newVendors []string) []string {
	for _, newVendor := range newVendors {
		if !common.Contains(vendors, newVendor) {
			vendors = append(vendors, newVendor)
		}
	}

	return vendors
}

func GetLastUpdatedImage(protoLastUpdated *proto_go.RepoLastUpdatedImage) *mTypes.LastUpdatedImage {
	if protoLastUpdated == nil {
		return nil
	}

	return &mTypes.LastUpdatedImage{
		Descriptor: mTypes.Descriptor{
			Digest:    protoLastUpdated.Digest,
			MediaType: protoLastUpdated.MediaType,
		},
		Tag:         protoLastUpdated.Tag,
		LastUpdated: GetTime(protoLastUpdated.LastUpdated),
	}
}

func GetImageMeta(dbImageMeta *proto_go.ImageMeta) mTypes.ImageMeta {
	if dbImageMeta == nil {
		return mTypes.ImageMeta{}
	}

	imageMeta := mTypes.ImageMeta{
		MediaType: dbImageMeta.MediaType,
		Size:      GetImageManifestSize(dbImageMeta),
		Digest:    GetImageDigest(dbImageMeta),
	}

	if dbImageMeta.MediaType == ispec.MediaTypeImageIndex {
		manifests := make([]ispec.Descriptor, 0, len(dbImageMeta.Manifests))

		for _, manifest := range deref(dbImageMeta.Index, proto_go.IndexMeta{}).Index.Manifests {
			manifests = append(manifests, ispec.Descriptor{
				MediaType: manifest.MediaType,
				Digest:    godigest.Digest(manifest.Digest),
				Size:      manifest.Size,
			})
		}

		imageMeta.Index = &ispec.Index{
			Versioned:    specs.Versioned{SchemaVersion: int(dbImageMeta.Index.Index.Versioned.GetSchemaVersion())},
			MediaType:    ispec.MediaTypeImageIndex,
			Manifests:    manifests,
			Subject:      GetImageSubject(dbImageMeta),
			ArtifactType: GetImageArtifactType(dbImageMeta),
			Annotations:  GetImageAnnotations(dbImageMeta),
		}
	}

	manifestDataList := make([]mTypes.ManifestMeta, 0, len(dbImageMeta.Manifests))

	for _, manifest := range dbImageMeta.Manifests {
		manifestDataList = append(manifestDataList, mTypes.ManifestMeta{
			Size:   manifest.Size,
			Digest: godigest.Digest(manifest.Digest),
			Manifest: ispec.Manifest{
				Versioned:    specs.Versioned{SchemaVersion: int(manifest.Manifest.Versioned.GetSchemaVersion())},
				MediaType:    deref(manifest.Manifest.MediaType, ""),
				ArtifactType: deref(manifest.Manifest.ArtifactType, ""),
				Config: ispec.Descriptor{
					MediaType: manifest.Manifest.Config.MediaType,
					Size:      manifest.Manifest.Config.Size,
					Digest:    godigest.Digest(manifest.Manifest.Config.Digest),
				},
				Layers:      GetLayers(manifest.Manifest.Layers),
				Subject:     GetSubject(manifest.Manifest.Subject),
				Annotations: manifest.Manifest.Annotations,
			},
			Config: ispec.Image{
				Created:  GetTime(manifest.Config.Created),
				Author:   deref(manifest.Config.Author, ""),
				Platform: GetPlatform(manifest.Config.Platform),
				Config: ispec.ImageConfig{
					User:         manifest.Config.Config.User,
					ExposedPorts: GetExposedPorts(manifest.Config.Config.ExposedPorts),
					Env:          manifest.Config.Config.Env,
					Entrypoint:   manifest.Config.Config.Entrypoint,
					Cmd:          manifest.Config.Config.Cmd,
					Volumes:      GetConfigVolumes(manifest.Config.Config.Volumes),
					WorkingDir:   deref(manifest.Config.Config.WorkingDir, ""),
					Labels:       manifest.Config.Config.Labels,
					StopSignal:   deref(manifest.Config.Config.StopSignal, ""),
				},
				RootFS: ispec.RootFS{
					Type:    manifest.Config.RootFS.Type,
					DiffIDs: GetDiffIDs(manifest.Config.RootFS.DiffIDs),
				},
				History: GetHistory(manifest.Config.History),
			},
		})
	}

	imageMeta.Manifests = manifestDataList

	return imageMeta
}

func GetExposedPorts(exposedPorts map[string]*proto_go.EmptyMessage) map[string]struct{} {
	if exposedPorts == nil {
		return nil
	}

	result := map[string]struct{}{}

	for key := range exposedPorts {
		result[key] = struct{}{}
	}

	return result
}

func GetConfigVolumes(configVolumes map[string]*proto_go.EmptyMessage) map[string]struct{} {
	if configVolumes == nil {
		return nil
	}

	result := map[string]struct{}{}

	for key := range configVolumes {
		result[key] = struct{}{}
	}

	return result
}

func GetDiffIDs(diffIDs []string) []godigest.Digest {
	result := make([]godigest.Digest, 0, len(diffIDs))

	for i := range diffIDs {
		result = append(result, godigest.Digest(diffIDs[i]))
	}

	return result
}
