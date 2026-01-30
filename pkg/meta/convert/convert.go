package convert

import (
	"slices"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"zotregistry.dev/zot/v2/pkg/compat"
	proto_go "zotregistry.dev/zot/v2/pkg/meta/proto/gen"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
)

func GetHistory(history []*proto_go.History) []ispec.History {
	if history == nil {
		return nil
	}

	results := make([]ispec.History, 0, len(history))

	for _, his := range history {
		results = append(results, ispec.History{
			Created:    ref(his.GetCreated().AsTime()),
			CreatedBy:  his.GetCreatedBy(),
			Author:     his.GetAuthor(),
			Comment:    his.GetComment(),
			EmptyLayer: his.GetEmptyLayer(),
		})
	}

	return results
}

func GetImageArtifactType(imageMeta *proto_go.ImageMeta) string {
	mediaType := imageMeta.GetMediaType()

	switch {
	case mediaType == ispec.MediaTypeImageManifest || compat.IsCompatibleManifestMediaType(mediaType):
		manifestArtifactType := imageMeta.GetManifests()[0].GetManifest().GetArtifactType()
		if manifestArtifactType != "" {
			return manifestArtifactType
		}

		return imageMeta.GetManifests()[0].GetManifest().GetConfig().GetMediaType()
	case mediaType == ispec.MediaTypeImageIndex || compat.IsCompatibleManifestListMediaType(mediaType):
		return imageMeta.GetIndex().GetIndex().GetArtifactType()
	default:
		return ""
	}
}

func GetImageManifestSize(imageMeta *proto_go.ImageMeta) int64 {
	mediaType := imageMeta.GetMediaType()

	switch {
	case mediaType == ispec.MediaTypeImageManifest || compat.IsCompatibleManifestMediaType(mediaType):
		return imageMeta.GetManifests()[0].GetSize()
	case mediaType == ispec.MediaTypeImageIndex || compat.IsCompatibleManifestListMediaType(mediaType):
		return imageMeta.GetIndex().GetSize()
	default:
		return 0
	}
}

func GetImageDigest(imageMeta *proto_go.ImageMeta) godigest.Digest {
	mediaType := imageMeta.GetMediaType()

	switch {
	case mediaType == ispec.MediaTypeImageManifest || compat.IsCompatibleManifestMediaType(mediaType):
		return godigest.Digest(imageMeta.GetManifests()[0].GetDigest())
	case mediaType == ispec.MediaTypeImageIndex || compat.IsCompatibleManifestListMediaType(mediaType):
		return godigest.Digest(imageMeta.GetIndex().GetDigest())
	default:
		return ""
	}
}

func GetImageDigestStr(imageMeta *proto_go.ImageMeta) string {
	mediaType := imageMeta.GetMediaType()

	switch {
	case mediaType == ispec.MediaTypeImageManifest || compat.IsCompatibleManifestMediaType(mediaType):
		return imageMeta.GetManifests()[0].GetDigest()
	case mediaType == ispec.MediaTypeImageIndex || compat.IsCompatibleManifestListMediaType(mediaType):
		return imageMeta.GetIndex().GetDigest()
	default:
		return ""
	}
}

func GetImageAnnotations(imageMeta *proto_go.ImageMeta) map[string]string {
	mediaType := imageMeta.GetMediaType()

	switch {
	case mediaType == ispec.MediaTypeImageManifest || compat.IsCompatibleManifestMediaType(mediaType):
		return imageMeta.GetManifests()[0].GetManifest().GetAnnotations()
	case mediaType == ispec.MediaTypeImageIndex || compat.IsCompatibleManifestListMediaType(mediaType):
		return imageMeta.GetIndex().GetIndex().GetAnnotations()
	default:
		return map[string]string{}
	}
}

func GetImageSubject(imageMeta *proto_go.ImageMeta) *ispec.Descriptor {
	mediaType := imageMeta.GetMediaType()

	switch {
	case mediaType == ispec.MediaTypeImageManifest || compat.IsCompatibleManifestMediaType(mediaType):
		if imageMeta.GetManifests()[0].GetManifest().GetSubject() == nil {
			return nil
		}

		return GetDescriptorRef(imageMeta.GetManifests()[0].GetManifest().GetSubject())
	case mediaType == ispec.MediaTypeImageIndex || compat.IsCompatibleManifestListMediaType(mediaType):
		return GetDescriptorRef(imageMeta.GetIndex().GetIndex().GetSubject())
	default:
		return nil
	}
}

func GetDescriptorRef(descriptor *proto_go.Descriptor) *ispec.Descriptor {
	if descriptor == nil {
		return nil
	}

	platform := GetPlatformRef(descriptor.GetPlatform())

	return &ispec.Descriptor{
		MediaType:    descriptor.GetMediaType(),
		Digest:       godigest.Digest(descriptor.GetDigest()),
		Size:         descriptor.GetSize(),
		URLs:         descriptor.GetURLs(),
		Data:         descriptor.GetData(),
		Platform:     platform,
		ArtifactType: descriptor.GetArtifactType(),
		Annotations:  descriptor.GetAnnotations(),
	}
}

func GetPlatform(platform *proto_go.Platform) ispec.Platform {
	if platform == nil {
		return ispec.Platform{}
	}

	return ispec.Platform{
		Architecture: platform.GetArchitecture(),
		OS:           platform.GetOS(),
		OSVersion:    platform.GetOSVersion(),
		OSFeatures:   platform.GetOSFeatures(),
		Variant:      platform.GetVariant(),
	}
}

func GetPlatformRef(platform *proto_go.Platform) *ispec.Platform {
	if platform == nil {
		return nil
	}

	return &ispec.Platform{
		Architecture: platform.GetArchitecture(),
		OS:           platform.GetOS(),
		OSVersion:    platform.GetOSVersion(),
		OSFeatures:   platform.GetOSFeatures(),
		Variant:      platform.GetVariant(),
	}
}

func GetLayers(descriptors []*proto_go.Descriptor) []ispec.Descriptor {
	results := make([]ispec.Descriptor, 0, len(descriptors))

	for _, desc := range descriptors {
		results = append(results, ispec.Descriptor{
			MediaType: desc.GetMediaType(),
			Digest:    godigest.Digest(desc.GetDigest()),
			Size:      desc.GetSize(),
		})
	}

	return results
}

func GetSubject(subj *proto_go.Descriptor) *ispec.Descriptor {
	if subj == nil {
		return nil
	}

	return &ispec.Descriptor{
		MediaType: subj.GetMediaType(),
		Digest:    godigest.Digest(subj.GetDigest()),
		Size:      subj.GetSize(),
	}
}

func GetReferrers(refs map[string]*proto_go.ReferrersInfo) map[string][]mTypes.ReferrerInfo {
	results := map[string][]mTypes.ReferrerInfo{}

	for digest, ref := range refs {
		referrers := []mTypes.ReferrerInfo{}

		for _, dbRef := range ref.GetList() {
			referrers = append(referrers, mTypes.ReferrerInfo{
				Digest:       dbRef.GetDigest(),
				MediaType:    dbRef.GetMediaType(),
				ArtifactType: dbRef.GetArtifactType(),
				Size:         int(dbRef.GetSize()), // int64 to int32, need to review this later
				Annotations:  dbRef.GetAnnotations(),
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

	for _, dbRef := range refs.GetList() {
		results = append(results, mTypes.ReferrerInfo{
			Digest:       dbRef.GetDigest(),
			MediaType:    dbRef.GetMediaType(),
			ArtifactType: dbRef.GetArtifactType(),
			Size:         int(dbRef.GetSize()), // int64 to int32, need to review this later
			Annotations:  dbRef.GetAnnotations(),
		})
	}

	return results
}

func GetSignatures(sigs map[string]*proto_go.ManifestSignatures) map[string]mTypes.ManifestSignatures {
	results := map[string]mTypes.ManifestSignatures{}

	for digest, dbSignatures := range sigs {
		imageSignatures := mTypes.ManifestSignatures{}

		for signatureName, signatureInfo := range dbSignatures.GetMap() {
			imageSignatures[signatureName] = GetSignaturesInfo(signatureInfo.GetList())
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

	for signatureName, signatureInfo := range sigs.GetMap() {
		results[signatureName] = GetSignaturesInfo(signatureInfo.GetList())
	}

	return results
}

func GetSignaturesInfo(sigsInfo []*proto_go.SignatureInfo) []mTypes.SignatureInfo {
	results := []mTypes.SignatureInfo{}

	for _, siginfo := range sigsInfo {
		results = append(results, mTypes.SignatureInfo{
			SignatureManifestDigest: siginfo.GetSignatureManifestDigest(),
			LayersInfo:              GetLayersInfo(siginfo.GetLayersInfo()),
		})
	}

	return results
}

func GetLayersInfo(layersInfo []*proto_go.LayersInfo) []mTypes.LayerInfo {
	results := []mTypes.LayerInfo{}

	for _, layerInfo := range layersInfo {
		date := time.Time{}

		if layerInfo.GetDate() != nil {
			date = layerInfo.GetDate().AsTime()
		}

		results = append(results, mTypes.LayerInfo{
			LayerDigest:  layerInfo.GetLayerDigest(),
			LayerContent: layerInfo.GetLayerContent(),
			SignatureKey: layerInfo.GetSignatureKey(),
			Signer:       layerInfo.GetSigner(),
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
			DownloadCount:     int(stat.GetDownloadCount()),
			LastPullTimestamp: stat.GetLastPullTimestamp().AsTime(),
			PushTimestamp:     stat.GetPushTimestamp().AsTime(),
			PushedBy:          stat.GetPushedBy(),
		}
	}

	return results
}

func GetImageStatistics(stats *proto_go.DescriptorStatistics) mTypes.DescriptorStatistics {
	if stats == nil {
		return mTypes.DescriptorStatistics{}
	}

	return mTypes.DescriptorStatistics{
		DownloadCount:     int(stats.GetDownloadCount()),
		LastPullTimestamp: stats.GetLastPullTimestamp().AsTime(),
		PushTimestamp:     stats.GetPushTimestamp().AsTime(),
		PushedBy:          stats.GetPushedBy(),
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
		taggedTimestamp := time.Time{}
		if tagDescriptor.GetTaggedTimestamp() != nil {
			taggedTimestamp = tagDescriptor.GetTaggedTimestamp().AsTime()
		}
		resultMap[tag] = mTypes.Descriptor{
			Digest:          tagDescriptor.GetDigest(),
			MediaType:       tagDescriptor.GetMediaType(),
			TaggedTimestamp: taggedTimestamp,
		}
	}

	return resultMap
}

func GetManifests(descriptors []ispec.Descriptor) []mTypes.ManifestMeta {
	manifestList := []mTypes.ManifestMeta{}

	for _, manifest := range descriptors {
		mediaType := manifest.MediaType

		// let's filter out unexpected media types from the manifest lists,
		// this could be the case of buildkit cache entries for example
		if mediaType == ispec.MediaTypeImageManifest || compat.IsCompatibleManifestMediaType(mediaType) ||
			mediaType == ispec.MediaTypeImageIndex || compat.IsCompatibleManifestListMediaType(mediaType) {
			manifestList = append(manifestList, mTypes.ManifestMeta{
				Digest: manifest.Digest,
				Size:   manifest.Size,
			})
		}
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

	taggedTimestamp := time.Time{}
	if tagDescriptor, ok := protoRepoMeta.GetTags()[tag]; ok && tagDescriptor.GetTaggedTimestamp() != nil {
		taggedTimestamp = tagDescriptor.GetTaggedTimestamp().AsTime()
	}

	return mTypes.FullImageMeta{
		Repo:            protoRepoMeta.GetName(),
		Tag:             tag,
		MediaType:       imageMeta.MediaType,
		Digest:          imageMeta.Digest,
		Size:            imageMeta.Size,
		Index:           imageMeta.Index,
		Manifests:       GetFullManifestData(protoRepoMeta, imageMeta.Manifests),
		IsStarred:       protoRepoMeta.GetIsStarred(),
		IsBookmarked:    protoRepoMeta.GetIsBookmarked(),
		TaggedTimestamp: taggedTimestamp,

		Referrers:  GetImageReferrers(protoRepoMeta.GetReferrers()[imageDigest]),
		Statistics: GetImageStatistics(protoRepoMeta.GetStatistics()[imageDigest]),
		Signatures: GetImageSignatures(protoRepoMeta.GetSignatures()[imageDigest]),
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
			Referrers:    GetImageReferrers(protoRepoMeta.GetReferrers()[manifestData[i].Digest.String()]),
			Statistics:   GetImageStatistics(protoRepoMeta.GetStatistics()[manifestData[i].Digest.String()]),
			Signatures:   GetImageSignatures(protoRepoMeta.GetSignatures()[manifestData[i].Digest.String()]),
		})
	}

	return results
}

func GetRepoMeta(protoRepoMeta *proto_go.RepoMeta) mTypes.RepoMeta {
	if protoRepoMeta == nil {
		return mTypes.RepoMeta{}
	}

	repoDownloads := int32(0)

	for _, descriptor := range protoRepoMeta.GetTags() {
		if statistic := protoRepoMeta.GetStatistics()[descriptor.GetDigest()]; statistic != nil {
			repoDownloads += statistic.GetDownloadCount()
		}
	}

	return mTypes.RepoMeta{
		Name:             protoRepoMeta.GetName(),
		Tags:             GetTags(protoRepoMeta.GetTags()),
		Rank:             int(protoRepoMeta.GetRank()),
		Size:             protoRepoMeta.GetSize(),
		Platforms:        GetPlatforms(protoRepoMeta.GetPlatforms()),
		Vendors:          protoRepoMeta.GetVendors(),
		IsStarred:        protoRepoMeta.GetIsStarred(),
		IsBookmarked:     protoRepoMeta.GetIsBookmarked(),
		StarCount:        int(protoRepoMeta.GetStars()),
		DownloadCount:    int(repoDownloads),
		LastUpdatedImage: GetLastUpdatedImage(protoRepoMeta.GetLastUpdatedImage()),
		Statistics:       GetStatisticsMap(protoRepoMeta.GetStatistics()),
		Signatures:       GetSignatures(protoRepoMeta.GetSignatures()),
		Referrers:        GetReferrers(protoRepoMeta.GetReferrers()),
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
	return slices.ContainsFunc(platforms, func(p *proto_go.Platform) bool {
		return p.GetOS() == platform.GetOS() && p.GetArchitecture() == platform.GetArchitecture()
	})
}

func AddVendors(vendors []string, newVendors []string) []string {
	for _, newVendor := range newVendors {
		if !slices.Contains(vendors, newVendor) {
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
			Digest:    protoLastUpdated.GetDigest(),
			MediaType: protoLastUpdated.GetMediaType(),
		},
		Tag:         protoLastUpdated.GetTag(),
		LastUpdated: GetTime(protoLastUpdated.GetLastUpdated()),
	}
}

func GetImageMeta(dbImageMeta *proto_go.ImageMeta) mTypes.ImageMeta {
	if dbImageMeta == nil {
		return mTypes.ImageMeta{}
	}

	imageMeta := mTypes.ImageMeta{
		MediaType: dbImageMeta.GetMediaType(),
		Size:      GetImageManifestSize(dbImageMeta),
		Digest:    GetImageDigest(dbImageMeta),
	}

	if dbImageMeta.GetMediaType() == ispec.MediaTypeImageIndex ||
		compat.IsCompatibleManifestListMediaType(dbImageMeta.GetMediaType()) {
		manifests := make([]ispec.Descriptor, 0, len(dbImageMeta.GetManifests()))

		for _, manifest := range dbImageMeta.GetIndex().GetIndex().GetManifests() {
			desc := ispec.Descriptor{
				MediaType:   manifest.GetMediaType(),
				Digest:      godigest.Digest(manifest.GetDigest()),
				Size:        manifest.GetSize(),
				Annotations: manifest.Annotations,
			}

			if manifest.Platform != nil {
				platform := GetPlatform(manifest.Platform)
				desc.Platform = &platform
			}

			manifests = append(manifests, desc)
		}

		imageMeta.Index = &ispec.Index{
			Versioned:    specs.Versioned{SchemaVersion: int(dbImageMeta.GetIndex().GetIndex().Versioned.GetSchemaVersion())},
			MediaType:    ispec.MediaTypeImageIndex,
			Manifests:    manifests,
			Subject:      GetImageSubject(dbImageMeta),
			ArtifactType: GetImageArtifactType(dbImageMeta),
			Annotations:  GetImageAnnotations(dbImageMeta),
		}
	}

	manifestDataList := make([]mTypes.ManifestMeta, 0, len(dbImageMeta.GetManifests()))

	for _, manifest := range dbImageMeta.GetManifests() {
		manifestDataList = append(manifestDataList, mTypes.ManifestMeta{
			Size:   manifest.GetSize(),
			Digest: godigest.Digest(manifest.GetDigest()),
			Manifest: ispec.Manifest{
				Versioned:    specs.Versioned{SchemaVersion: int(manifest.GetManifest().GetVersioned().GetSchemaVersion())},
				MediaType:    manifest.GetManifest().GetMediaType(),
				ArtifactType: manifest.GetManifest().GetArtifactType(),
				Config: ispec.Descriptor{
					MediaType: manifest.GetManifest().GetConfig().GetMediaType(),
					Size:      manifest.GetManifest().GetConfig().GetSize(),
					Digest:    godigest.Digest(manifest.GetManifest().GetConfig().GetDigest()),
				},
				Layers:      GetLayers(manifest.GetManifest().GetLayers()),
				Subject:     GetSubject(manifest.GetManifest().GetSubject()),
				Annotations: manifest.GetManifest().GetAnnotations(),
			},
			Config: ispec.Image{
				Created:  GetTime(manifest.GetConfig().GetCreated()),
				Author:   manifest.GetConfig().GetAuthor(),
				Platform: GetPlatform(manifest.GetConfig().GetPlatform()),
				Config: ispec.ImageConfig{
					User:         manifest.GetConfig().GetConfig().GetUser(),
					ExposedPorts: GetExposedPorts(manifest.GetConfig().GetConfig().GetExposedPorts()),
					Env:          manifest.GetConfig().GetConfig().GetEnv(),
					Entrypoint:   manifest.GetConfig().GetConfig().GetEntrypoint(),
					Cmd:          manifest.GetConfig().GetConfig().GetCmd(),
					Volumes:      GetConfigVolumes(manifest.GetConfig().GetConfig().GetVolumes()),
					WorkingDir:   manifest.GetConfig().GetConfig().GetWorkingDir(),
					Labels:       manifest.GetConfig().GetConfig().GetLabels(),
					StopSignal:   manifest.GetConfig().GetConfig().GetStopSignal(),
				},
				RootFS: ispec.RootFS{
					Type:    manifest.GetConfig().GetRootFS().GetType(),
					DiffIDs: GetDiffIDs(manifest.GetConfig().GetRootFS().GetDiffIDs()),
				},
				History: GetHistory(manifest.GetConfig().GetHistory()),
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
