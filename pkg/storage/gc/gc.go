package gc

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"path"
	"strings"
	"time"

	"github.com/docker/distribution/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	zcommon "zotregistry.dev/zot/pkg/common"
	zlog "zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/retention"
	rTypes "zotregistry.dev/zot/pkg/retention/types"
	"zotregistry.dev/zot/pkg/scheduler"
	"zotregistry.dev/zot/pkg/storage"
	common "zotregistry.dev/zot/pkg/storage/common"
	"zotregistry.dev/zot/pkg/storage/types"
)

const (
	cosignSignatureTagSuffix = "sig"
	SBOMTagSuffix            = "sbom"
)

type Options struct {
	// will garbage collect blobs older than Delay
	Delay time.Duration

	ImageRetention config.ImageRetention
}

type GarbageCollect struct {
	imgStore  types.ImageStore
	opts      Options
	metaDB    mTypes.MetaDB
	policyMgr rTypes.PolicyManager
	auditLog  *zlog.Logger
	log       zlog.Logger
}

func NewGarbageCollect(imgStore types.ImageStore, metaDB mTypes.MetaDB, opts Options,
	auditLog *zlog.Logger, log zlog.Logger,
) GarbageCollect {
	return GarbageCollect{
		imgStore:  imgStore,
		metaDB:    metaDB,
		opts:      opts,
		policyMgr: retention.NewPolicyManager(opts.ImageRetention, log, auditLog),
		auditLog:  auditLog,
		log:       log,
	}
}

/*
CleanImageStorePeriodically runs a periodic garbage collect on the ImageStore provided in constructor,
given an interval and a Scheduler.
*/
func (gc GarbageCollect) CleanImageStorePeriodically(interval time.Duration, sch *scheduler.Scheduler) {
	generator := &GCTaskGenerator{
		imgStore: gc.imgStore,
		gc:       gc,
	}

	sch.SubmitGenerator(generator, interval, scheduler.MediumPriority)
}

/*
CleanRepo executes a garbage collection of any blob found in storage which is not referenced
in any manifests referenced in repo's index.json
It also gc referrers with missing subject if the Referrer Option is enabled
It also gc untagged manifests.
*/
func (gc GarbageCollect) CleanRepo(ctx context.Context, repo string) error {
	gc.log.Info().Str("module", "gc").
		Msg(fmt.Sprintf("executing GC of orphaned blobs for %s", path.Join(gc.imgStore.RootDir(), repo)))

	if err := gc.cleanRepo(ctx, repo); err != nil {
		errMessage := fmt.Sprintf("failed to run GC for %s", path.Join(gc.imgStore.RootDir(), repo))
		gc.log.Error().Err(err).Str("module", "gc").Msg(errMessage)
		gc.log.Info().Str("module", "gc").
			Msg(fmt.Sprintf("GC unsuccessfully completed for %s", path.Join(gc.imgStore.RootDir(), repo)))

		return err
	}

	gc.log.Info().Str("module", "gc").
		Msg(fmt.Sprintf("GC successfully completed for %s", path.Join(gc.imgStore.RootDir(), repo)))

	return nil
}

func (gc GarbageCollect) cleanRepo(ctx context.Context, repo string) error {
	var lockLatency time.Time

	dir := path.Join(gc.imgStore.RootDir(), repo)
	if !gc.imgStore.DirExists(dir) {
		return zerr.ErrRepoNotFound
	}

	gc.imgStore.Lock(&lockLatency)
	defer gc.imgStore.Unlock(&lockLatency)

	/* this index (which represents the index.json of this repo) is the root point from which we
	search for dangling manifests/blobs
	so this index is passed by reference in all functions that modifies it

	Instead of removing manifests one by one with storage APIs we just remove manifests descriptors
	from index.Manifests[] list and update repo's index.json afterwards.

	After updating repo's index.json we clean all unreferenced blobs (manifests included).
	*/
	index, err := common.GetIndex(gc.imgStore, repo, gc.log)
	if err != nil {
		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).Msg("failed to read index.json in repo")

		return err
	}

	// apply tags retention
	if err := gc.removeTagsPerRetentionPolicy(ctx, repo, &index); err != nil {
		return err
	}

	// gc referrers manifests with missing subject and untagged manifests
	if err := gc.removeManifestsPerRepoPolicy(ctx, repo, &index); err != nil {
		return err
	}

	// update repos's index.json in storage
	if !gc.opts.ImageRetention.DryRun {
		/* this will update the index.json with manifests deleted above
		and the manifests blobs will be removed by gc.removeUnreferencedBlobs()*/
		if err := gc.imgStore.PutIndexContent(repo, index); err != nil {
			return err
		}
	}

	// gc unreferenced blobs
	if err := gc.removeUnreferencedBlobs(repo, gc.opts.Delay, gc.log); err != nil {
		return err
	}

	return nil
}

func (gc GarbageCollect) removeManifestsPerRepoPolicy(ctx context.Context, repo string, index *ispec.Index) error {
	var err error

	/* gc all manifests that have a missing subject, stop when neither gc(referrer and untagged)
	happened in a full loop over index.json. */
	var stop bool
	for !stop {
		if zcommon.IsContextDone(ctx) {
			return ctx.Err()
		}

		var gcedReferrer bool

		var gcedUntagged bool

		if gc.policyMgr.HasDeleteReferrer(repo) {
			gc.log.Debug().Str("module", "gc").Str("repository", repo).Msg("manifests with missing referrers")

			gcedReferrer, err = gc.removeIndexReferrers(repo, index, *index)
			if err != nil {
				return err
			}
		}

		if gc.policyMgr.HasDeleteUntagged(repo) {
			referenced := make(map[godigest.Digest]bool, 0)

			/* gather all manifests referenced in multiarch images/by other manifests
			so that we can skip them in cleanUntaggedManifests */
			if err := gc.identifyManifestsReferencedInIndex(*index, repo, referenced); err != nil {
				return err
			}

			// apply image retention policy
			gcedUntagged, err = gc.removeUntaggedManifests(repo, index, referenced)
			if err != nil {
				return err
			}
		}

		/* if we gced any manifest then loop again and gc manifests with
		a subject pointing to the last ones which were gced. */
		stop = !gcedReferrer && !gcedUntagged
	}

	return nil
}

/*
garbageCollectIndexReferrers will gc all referrers with a missing subject recursively

rootIndex is indexJson, need to pass it down to garbageCollectReferrer()
rootIndex is the place we look for referrers.
*/
func (gc GarbageCollect) removeIndexReferrers(repo string, rootIndex *ispec.Index, index ispec.Index,
) (bool, error) {
	var count int

	var err error

	for _, desc := range index.Manifests {
		switch desc.MediaType {
		case ispec.MediaTypeImageIndex:
			indexImage, err := common.GetImageIndex(gc.imgStore, repo, desc.Digest, gc.log)
			if err != nil {
				gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).Str("digest", desc.Digest.String()).
					Msg("failed to read multiarch(index) image")

				return false, err
			}

			gced, err := gc.removeReferrer(repo, rootIndex, desc, indexImage.Subject, indexImage.ArtifactType)
			if err != nil {
				return false, err
			}

			/* if we gc index then no need to continue searching for referrers inside it.
			they will be gced when the next garbage collect is executed(if they are older than retentionDelay),
			 because manifests part of indexes will still be referenced in index.json */
			if gced {
				return true, nil
			}

			gced, err = gc.removeIndexReferrers(repo, rootIndex, indexImage)
			if err != nil {
				return false, err
			}

			if gced {
				count++
			}
		case ispec.MediaTypeImageManifest:
			image, err := common.GetImageManifest(gc.imgStore, repo, desc.Digest, gc.log)
			if err != nil {
				gc.log.Error().Err(err).Str("module", "gc").Str("repo", repo).Str("digest", desc.Digest.String()).
					Msg("failed to read manifest image")

				return false, err
			}

			artifactType := zcommon.GetManifestArtifactType(image)

			gced, err := gc.removeReferrer(repo, rootIndex, desc, image.Subject, artifactType)
			if err != nil {
				return false, err
			}

			if gced {
				count++
			}
		}
	}

	return count > 0, err
}

func (gc GarbageCollect) removeReferrer(repo string, index *ispec.Index, manifestDesc ispec.Descriptor,
	subject *ispec.Descriptor, artifactType string,
) (bool, error) {
	var gced bool

	var err error

	if subject != nil {
		// try to find subject in index.json
		referenced := isManifestReferencedInIndex(index, subject.Digest)

		var signatureType string
		// check if its notation or cosign signature
		if artifactType == zcommon.ArtifactTypeNotation {
			signatureType = storage.NotationType
		} else if artifactType == zcommon.ArtifactTypeCosign {
			signatureType = storage.CosignType
		}

		if !referenced {
			gced, err = gc.gcManifest(repo, index, manifestDesc, signatureType, subject.Digest, gc.opts.ImageRetention.Delay)
			if err != nil {
				return false, err
			}

			if gced {
				gc.log.Info().Str("module", "gc").
					Str("repository", repo).
					Str("reference", manifestDesc.Digest.String()).
					Str("subject", subject.Digest.String()).
					Str("decision", "delete").
					Str("reason", "deleteReferrers").Msg("removed manifest without reference")

				if gc.auditLog != nil {
					gc.auditLog.Info().Str("module", "gc").
						Str("repository", repo).
						Str("reference", manifestDesc.Digest.String()).
						Str("subject", subject.Digest.String()).
						Str("decision", "delete").
						Str("reason", "deleteReferrers").Msg("removed manifest without reference")
				}
			}
		}
	}

	// cosign
	tag, ok := getDescriptorTag(manifestDesc)
	if ok {
		if isCosignTag(tag) {
			subjectDigest := getSubjectFromCosignTag(tag)
			referenced := isManifestReferencedInIndex(index, subjectDigest)

			if !referenced {
				gced, err = gc.gcManifest(repo, index, manifestDesc, storage.CosignType, subjectDigest, gc.opts.Delay)
				if err != nil {
					return false, err
				}

				if gced {
					gc.log.Info().Str("module", "gc").
						Bool("dry-run", gc.opts.ImageRetention.DryRun).
						Str("repository", repo).
						Str("reference", tag).
						Str("subject", subjectDigest.String()).
						Str("decision", "delete").
						Str("reason", "deleteReferrers").Msg("removed cosign manifest without reference")

					if gc.auditLog != nil {
						gc.auditLog.Info().Str("module", "gc").
							Bool("dry-run", gc.opts.ImageRetention.DryRun).
							Str("repository", repo).
							Str("reference", tag).
							Str("subject", subjectDigest.String()).
							Str("decision", "delete").
							Str("reason", "deleteReferrers").Msg("removed cosign manifest without reference")
					}
				}
			}
		}
	}

	return gced, nil
}

func (gc GarbageCollect) removeTagsPerRetentionPolicy(ctx context.Context, repo string, index *ispec.Index) error {
	if !gc.policyMgr.HasTagRetention(repo) {
		return nil
	}

	repoMeta, err := gc.metaDB.GetRepoMeta(ctx, repo)
	if err != nil {
		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).
			Msg("failed to get repoMeta")

		return err
	}

	retainTags := gc.policyMgr.GetRetainedTags(ctx, repoMeta, *index)

	// remove
	for _, desc := range index.Manifests {
		if zcommon.IsContextDone(ctx) {
			return ctx.Err()
		}

		// check tag
		tag, ok := getDescriptorTag(desc)
		if ok && !zcommon.Contains(retainTags, tag) {
			// remove tags which should not be retained
			_, err := gc.removeManifest(repo, index, desc, tag, "", "")
			if err != nil && !errors.Is(err, zerr.ErrManifestNotFound) {
				return err
			}
		}
	}

	return nil
}

// gcManifest removes a manifest entry from an index and syncs metaDB accordingly if the blob is older than gc.Delay.
func (gc GarbageCollect) gcManifest(repo string, index *ispec.Index, desc ispec.Descriptor,
	signatureType string, subjectDigest godigest.Digest, delay time.Duration,
) (bool, error) {
	var gced bool

	canGC, err := isBlobOlderThan(gc.imgStore, repo, desc.Digest, delay, gc.log)
	if err != nil {
		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).Str("digest", desc.Digest.String()).
			Str("delay", delay.String()).Msg("failed to check if blob is older than delay")

		return false, err
	}

	if canGC {
		if gced, err = gc.removeManifest(repo, index, desc, desc.Digest.String(), signatureType, subjectDigest); err != nil {
			return false, err
		}
	}

	return gced, nil
}

// removeManifest removes a manifest entry from an index and syncs metaDB accordingly.
func (gc GarbageCollect) removeManifest(repo string, index *ispec.Index,
	desc ispec.Descriptor, reference string, signatureType string, subjectDigest godigest.Digest,
) (bool, error) {
	_, err := common.RemoveManifestDescByReference(index, reference, true)
	if err != nil {
		if errors.Is(err, zerr.ErrManifestConflict) {
			return false, nil
		}

		return false, err
	}

	if gc.opts.ImageRetention.DryRun {
		return true, nil
	}

	// sync metaDB
	if gc.metaDB != nil {
		if signatureType != "" {
			err = gc.metaDB.DeleteSignature(repo, subjectDigest, mTypes.SignatureMetadata{
				SignatureDigest: desc.Digest.String(),
				SignatureType:   signatureType,
			})
			if err != nil {
				gc.log.Error().Err(err).Str("module", "gc").Str("component", "metadb").
					Msg("failed to remove signature in metaDB")

				return false, err
			}
		} else {
			err := gc.metaDB.RemoveRepoReference(repo, reference, desc.Digest)
			if err != nil {
				gc.log.Error().Err(err).Str("module", "gc").Str("component", "metadb").
					Msg("failed to remove repo reference in metaDB")

				return false, err
			}
		}
	}

	return true, nil
}

func (gc GarbageCollect) removeUntaggedManifests(repo string, index *ispec.Index,
	referenced map[godigest.Digest]bool,
) (bool, error) {
	var gced bool

	var err error

	gc.log.Debug().Str("module", "gc").Str("repository", repo).Msg("manifests without tags")

	for _, desc := range index.Manifests {
		// skip manifests referenced in image indexes
		if _, referenced := referenced[desc.Digest]; referenced {
			continue
		}

		// remove untagged images
		if desc.MediaType == ispec.MediaTypeImageManifest || desc.MediaType == ispec.MediaTypeImageIndex {
			_, ok := getDescriptorTag(desc)
			if !ok {
				gced, err = gc.gcManifest(repo, index, desc, "", "", gc.opts.ImageRetention.Delay)
				if err != nil {
					return false, err
				}

				if gced {
					gc.log.Info().Str("module", "gc").
						Bool("dry-run", gc.opts.ImageRetention.DryRun).
						Str("repository", repo).
						Str("reference", desc.Digest.String()).
						Str("decision", "delete").
						Str("reason", "deleteUntagged").Msg("removed untagged manifest")

					if gc.auditLog != nil {
						gc.auditLog.Info().Str("module", "gc").
							Bool("dry-run", gc.opts.ImageRetention.DryRun).
							Str("repository", repo).
							Str("reference", desc.Digest.String()).
							Str("decision", "delete").
							Str("reason", "deleteUntagged").Msg("removed untagged manifest")
					}
				}
			}
		}
	}

	return gced, nil
}

// Adds both referenced manifests and referrers from an index.
func (gc GarbageCollect) identifyManifestsReferencedInIndex(index ispec.Index, repo string,
	referenced map[godigest.Digest]bool,
) error {
	for _, desc := range index.Manifests {
		switch desc.MediaType {
		case ispec.MediaTypeImageIndex:
			indexImage, err := common.GetImageIndex(gc.imgStore, repo, desc.Digest, gc.log)
			if err != nil {
				gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).
					Str("digest", desc.Digest.String()).Msg("failed to read multiarch(index) image")

				return err
			}

			if indexImage.Subject != nil {
				referenced[desc.Digest] = true
			}

			for _, indexDesc := range indexImage.Manifests {
				referenced[indexDesc.Digest] = true
			}

			if err := gc.identifyManifestsReferencedInIndex(indexImage, repo, referenced); err != nil {
				return err
			}
		case ispec.MediaTypeImageManifest:
			image, err := common.GetImageManifest(gc.imgStore, repo, desc.Digest, gc.log)
			if err != nil {
				gc.log.Error().Err(err).Str("module", "gc").Str("repo", repo).
					Str("digest", desc.Digest.String()).Msg("failed to read manifest image")

				return err
			}

			if image.Subject != nil {
				referenced[desc.Digest] = true
			}
		}
	}

	return nil
}

// removeUnreferencedBlobs gc all blobs which are not referenced by any manifest found in repo's index.json.
func (gc GarbageCollect) removeUnreferencedBlobs(repo string, delay time.Duration, log zlog.Logger,
) error {
	gc.log.Debug().Str("module", "gc").Str("repository", repo).Msg("cleaning orphan blobs")

	refBlobs := map[string]bool{}

	index, err := common.GetIndex(gc.imgStore, repo, gc.log)
	if err != nil {
		log.Error().Err(err).Str("module", "gc").Str("repository", repo).Msg("failed to read index.json in repo")

		return err
	}

	err = gc.addIndexBlobsToReferences(repo, index, refBlobs)
	if err != nil {
		log.Error().Err(err).Str("module", "gc").Str("repository", repo).Msg("failed to get referenced blobs in repo")

		return err
	}

	allBlobs, err := gc.imgStore.GetAllBlobs(repo)
	if err != nil {
		// /blobs/sha256/ may be empty in the case of s3, no need to return err, we want to skip
		if errors.As(err, &driver.PathNotFoundError{}) {
			return nil
		}

		log.Error().Err(err).Str("module", "gc").Str("repository", repo).Msg("failed to get all blobs")

		return err
	}

	gcBlobs := make([]godigest.Digest, 0)

	for _, blob := range allBlobs {
		digest := godigest.NewDigestFromEncoded(godigest.SHA256, blob)
		if err = digest.Validate(); err != nil {
			log.Error().Err(err).Str("module", "gc").Str("repository", repo).Str("digest", blob).
				Msg("failed to parse digest")

			return err
		}

		if _, ok := refBlobs[digest.String()]; !ok {
			canGC, err := isBlobOlderThan(gc.imgStore, repo, digest, delay, log)
			if err != nil {
				log.Error().Err(err).Str("module", "gc").Str("repository", repo).Str("digest", blob).
					Msg("failed to determine GC delay")

				return err
			}

			if canGC {
				gcBlobs = append(gcBlobs, digest)
			}
		}
	}

	// if we removed all blobs from repo
	removeRepo := len(gcBlobs) > 0 && len(gcBlobs) == len(allBlobs)

	reaped, err := gc.imgStore.CleanupRepo(repo, gcBlobs, removeRepo)
	if err != nil {
		return err
	}

	log.Info().Str("module", "gc").Str("repository", repo).Int("count", reaped).
		Msg("garbage collected blobs")

	return nil
}

// used by removeUnreferencedBlobs()
// addIndexBlobsToReferences adds referenced blobs found in referenced manifests (index.json) in refblobs map.
func (gc GarbageCollect) addIndexBlobsToReferences(repo string, index ispec.Index, refBlobs map[string]bool,
) error {
	for _, desc := range index.Manifests {
		switch desc.MediaType {
		case ispec.MediaTypeImageIndex:
			if err := gc.addImageIndexBlobsToReferences(repo, desc.Digest, refBlobs); err != nil {
				gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).
					Str("digest", desc.Digest.String()).Msg("failed to read blobs in multiarch(index) image")

				return err
			}
		case ispec.MediaTypeImageManifest:
			if err := gc.addImageManifestBlobsToReferences(repo, desc.Digest, refBlobs); err != nil {
				gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).
					Str("digest", desc.Digest.String()).Msg("failed to read blobs in image manifest")

				return err
			}
		}
	}

	return nil
}

func (gc GarbageCollect) addImageIndexBlobsToReferences(repo string, mdigest godigest.Digest, refBlobs map[string]bool,
) error {
	index, err := common.GetImageIndex(gc.imgStore, repo, mdigest, gc.log)
	if err != nil {
		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).Str("digest", mdigest.String()).
			Msg("failed to read manifest image")

		return err
	}

	refBlobs[mdigest.String()] = true

	// if there is a Subject, it may not exist yet and that is ok
	if index.Subject != nil {
		refBlobs[index.Subject.Digest.String()] = true
	}

	for _, manifest := range index.Manifests {
		refBlobs[manifest.Digest.String()] = true
	}

	return nil
}

func (gc GarbageCollect) addImageManifestBlobsToReferences(repo string, mdigest godigest.Digest,
	refBlobs map[string]bool,
) error {
	manifestContent, err := common.GetImageManifest(gc.imgStore, repo, mdigest, gc.log)
	if err != nil {
		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).
			Str("digest", mdigest.String()).Msg("failed to read manifest image")

		return err
	}

	refBlobs[mdigest.String()] = true
	refBlobs[manifestContent.Config.Digest.String()] = true

	// if there is a Subject, it may not exist yet and that is ok
	if manifestContent.Subject != nil {
		refBlobs[manifestContent.Subject.Digest.String()] = true
	}

	for _, layer := range manifestContent.Layers {
		refBlobs[layer.Digest.String()] = true
	}

	return nil
}

func isManifestReferencedInIndex(index *ispec.Index, digest godigest.Digest) bool {
	for _, manifest := range index.Manifests {
		if manifest.Digest == digest {
			return true
		}
	}

	return false
}

func isBlobOlderThan(imgStore types.ImageStore, repo string,
	digest godigest.Digest, delay time.Duration, log zlog.Logger,
) (bool, error) {
	_, _, modtime, err := imgStore.StatBlob(repo, digest)
	if err != nil {
		log.Error().Err(err).Str("module", "gc").Str("repository", repo).Str("digest", digest.String()).
			Msg("failed to stat blob")

		return false, err
	}

	if modtime.Add(delay).After(time.Now()) {
		return false, nil
	}

	return true, nil
}

func getSubjectFromCosignTag(tag string) godigest.Digest {
	alg := strings.Split(tag, "-")[0]
	encoded := strings.Split(strings.Split(tag, "-")[1], ".sig")[0]

	return godigest.NewDigestFromEncoded(godigest.Algorithm(alg), encoded)
}

func getDescriptorTag(desc ispec.Descriptor) (string, bool) {
	tag, ok := desc.Annotations[ispec.AnnotationRefName]

	return tag, ok
}

// this function will check if tag is a cosign tag (signature or sbom).
func isCosignTag(tag string) bool {
	if strings.HasPrefix(tag, "sha256-") &&
		(strings.HasSuffix(tag, cosignSignatureTagSuffix) || strings.HasSuffix(tag, SBOMTagSuffix)) {
		return true
	}

	return false
}

/*
	GCTaskGenerator takes all repositories found in the storage.imagestore

and it will execute garbage collection for each repository by creating a task
for each repository and pushing it to the task scheduler.
*/
type GCTaskGenerator struct {
	imgStore types.ImageStore
	gc       GarbageCollect
	lastRepo string
	nextRun  time.Time
	done     bool
	rand     *rand.Rand
}

func (gen *GCTaskGenerator) getRandomDelay() int {
	maxDelay := 30

	return gen.rand.Intn(maxDelay)
}

func (gen *GCTaskGenerator) Name() string {
	return "GCTaskGenerator"
}

func (gen *GCTaskGenerator) Next() (scheduler.Task, error) {
	if gen.lastRepo == "" && gen.nextRun.IsZero() {
		gen.rand = rand.New(rand.NewSource(time.Now().UTC().UnixNano())) //nolint: gosec
	}

	delay := gen.getRandomDelay()

	gen.nextRun = time.Now().Add(time.Duration(delay) * time.Second)

	repo, err := gen.imgStore.GetNextRepository(gen.lastRepo)
	if err != nil {
		return nil, err
	}

	if repo == "" {
		gen.done = true

		return nil, nil
	}

	gen.lastRepo = repo

	return NewGCTask(gen.imgStore, gen.gc, repo), nil
}

func (gen *GCTaskGenerator) IsDone() bool {
	return gen.done
}

func (gen *GCTaskGenerator) IsReady() bool {
	return time.Now().After(gen.nextRun)
}

func (gen *GCTaskGenerator) Reset() {
	gen.lastRepo = ""
	gen.done = false
	gen.nextRun = time.Time{}
}

type gcTask struct {
	imgStore types.ImageStore
	gc       GarbageCollect
	repo     string
}

func NewGCTask(imgStore types.ImageStore, gc GarbageCollect, repo string,
) *gcTask {
	return &gcTask{imgStore, gc, repo}
}

func (gct *gcTask) DoWork(ctx context.Context) error {
	// run task
	return gct.gc.CleanRepo(ctx, gct.repo) //nolint: contextcheck
}

func (gct *gcTask) String() string {
	return fmt.Sprintf("{Name: %s, repo: %s}",
		gct.Name(), gct.repo)
}

func (gct *gcTask) Name() string {
	return "GCTask"
}
