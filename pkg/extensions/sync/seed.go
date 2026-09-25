//go:build sync

package sync

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/ref"

	storageCommon "zotregistry.dev/zot/v2/pkg/storage/common"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// seedOutcome is the state of one manifest or blob seed.
type seedOutcome struct {
	done     chan struct{}
	complete bool
}

// refSeeder holds the walk state of a single seedRef call.
type refSeeder struct {
	service    *BaseService
	imageStore storageTypes.ImageStore
	// tempStore is an ImageStore over the temp session dir behind the copy
	// target, the same store CommitAll later reads the session dir with.
	tempStore storageTypes.ImageStore
	localRepo string
	// remoteImageRef is used to fetch manifests missing from the local store.
	remoteImageRef ref.Ref

	// slots bounds concurrent fetch/copy operations
	slots chan struct{}
	// Map of each manifest or blob to its seed outcome
	manifests sync.Map
	blobs     sync.Map
	seeded    atomic.Int64
}

// acquire takes a fetch/copy slot and returns its release func. Slots are held
// only around leaf operations, never while recursing into children or waiting
// on another goroutine's outcome, so the bounded pool cannot deadlock.
func (seeder *refSeeder) acquire() func() {
	seeder.slots <- struct{}{}

	return func() { <-seeder.slots }
}

// claim returns the outcome for digest, creating it if this caller is the
// first: exactly one goroutine seeds each manifest or blob, everyone else
// waits for its result.
func claim(outcomes *sync.Map, digest godigest.Digest) (*seedOutcome, bool) {
	value, loaded := outcomes.LoadOrStore(digest, &seedOutcome{done: make(chan struct{})})
	outcome := value.(*seedOutcome) //nolint:forcetypeassert // only *seedOutcome values are ever stored

	return outcome, !loaded
}

// seedManifest walks the manifest tree under digest and seeds every referenced
// layer and config blob present in the local store, reporting whether the
// complete subtree was seeded.
//
// ImageCopy assumes everything under a manifest is complete, so for now
// explicitly don't write the manifests themselves. That still saves the
// expensive blob fetch, but completeness is still validated by regclient.
func (seeder *refSeeder) seedManifest(ctx context.Context, digest godigest.Digest) bool {
	outcome, first := claim(&seeder.manifests, digest)
	if !first {
		// waiting cannot cycle back into this goroutine: manifest content is
		// digest-verified on read, so the walked tree is acyclic
		<-outcome.done

		return outcome.complete
	}
	defer close(outcome.done)

	man := seeder.fetchManifest(ctx, digest)
	if man == nil {
		return false
	}

	results := make(chan bool)
	pending := 0
	seed := func(work func() bool) {
		pending++

		go func() { results <- work() }()
	}

	// Whether we have seeded all blobs under a manifest. Currently unused, as
	// we only seed blobs - if we seed manifests, we must only seed them if all
	// child blobs are seeded (otherwise `regclient` skips the manifest).
	complete := true

	// every regclient manifest type implements exactly one of Indexer and Imager
	switch man := man.(type) {
	case manifest.Indexer:
		children, err := man.GetManifestList()
		if err != nil {
			return false
		}

		for _, child := range children {
			seed(func() bool { return seeder.seedManifest(ctx, child.Digest) })
		}
	case manifest.Imager:
		layers, err := man.GetLayers()
		if err != nil {
			return false
		}

		for _, layer := range layers {
			// commit-side copyManifest skips non-distributable blobs as well
			if storageCommon.IsNonDistributable(layer.MediaType) {
				continue
			}

			seed(func() bool { return seeder.seedBlob(ctx, layer) })
		}

		if config, err := man.GetConfig(); err == nil {
			seed(func() bool { return seeder.seedBlob(ctx, config) })
		} else {
			// e.g. docker schema1 has no config descriptor: its layers are still
			// worth seeding, but the subtree can never be marked complete
			complete = false
		}
	default:
		return false
	}

	for range pending {
		complete = <-results && complete
	}

	outcome.complete = complete

	return complete
}

// fetchManifest returns the parsed manifest for digest, from the local store
// when present and from upstream otherwise.
func (seeder *refSeeder) fetchManifest(ctx context.Context, digest godigest.Digest) manifest.Manifest {
	release := seeder.acquire()
	defer release()

	service := seeder.service

	content, err := seeder.localBlobContent(digest)
	if err == nil {
		// manifest.New errors on unrecognized formats and verifies the content
		// against digest
		man, err := manifest.New(manifest.WithRaw(content), manifest.WithDesc(descriptor.Descriptor{Digest: digest}))
		if err != nil {
			service.log.Debug().Err(err).Str("repo", seeder.localRepo).Str("digest", digest.String()).
				Msg("failed to parse local manifest, not seeding it")

			return nil
		}

		return man
	}

	man, err := service.rc.ManifestGet(ctx, seeder.remoteImageRef.SetDigest(digest.String()))
	if err != nil {
		service.log.Debug().Err(err).Str("repo", seeder.localRepo).Str("digest", digest.String()).
			Msg("manifest neither in local storage nor upstream, nothing to seed under it")

		return nil
	}
	// the manifest body is already buffered; Close only releases per-ref resources
	defer service.rc.Close(ctx, man.GetRef())

	return man
}

// localBlobContent reads a manifest-sized blob from the local store, taking
// the read lock GetBlobContent requires its caller to hold.
func (seeder *refSeeder) localBlobContent(digest godigest.Digest) ([]byte, error) {
	var lockLatency time.Time

	seeder.imageStore.RLock(&lockLatency)
	defer seeder.imageStore.RUnlock(&lockLatency)

	return seeder.imageStore.GetBlobContent(seeder.localRepo, digest)
}

// localBlobStat reports whether localRepo itself holds digest, taking the
// read lock StatBlob requires its caller to hold. Deliberately not CheckBlob:
// with dedupe enabled, CheckBlob can hydrate the digest into localRepo from
// any other repository in the store, without the access checks the blob API
// routes apply to such cross-repo copies.
func (seeder *refSeeder) localBlobStat(digest godigest.Digest) bool {
	var lockLatency time.Time

	seeder.imageStore.RLock(&lockLatency)
	defer seeder.imageStore.RUnlock(&lockLatency)

	found, _, _, err := seeder.imageStore.StatBlob(seeder.localRepo, digest)

	return err == nil && found
}

// seedBlob makes a blob from the local store available in the temp layout by
// streaming a digest-verified copy.
func (seeder *refSeeder) seedBlob(ctx context.Context, desc descriptor.Descriptor) bool {
	outcome, first := claim(&seeder.blobs, desc.Digest)
	if !first {
		// already seeded (or failing) through another manifest
		<-outcome.done

		return outcome.complete
	}
	defer close(outcome.done)

	release := seeder.acquire()
	defer release()

	outcome.complete = seeder.copyLocalBlob(ctx, desc)

	return outcome.complete
}

// copyLocalBlob does the seedBlob work, while the caller holds the claim on
// desc.Digest and a fetch/copy slot.
func (seeder *refSeeder) copyLocalBlob(ctx context.Context, desc descriptor.Descriptor) bool {
	service := seeder.service

	if !seeder.localBlobStat(desc.Digest) {
		return false
	}

	// Explicitly copy to keep each blob digest-verified. When the store shares
	// a filesystem with the temp dir, we could hardlink instead as an
	// optimization, should verify at least the file size in that case.
	blob, _, err := seeder.imageStore.GetBlob(seeder.localRepo, desc.Digest, desc.MediaType)
	if err != nil {
		service.log.Debug().Err(err).Str("repo", seeder.localRepo).Str("digest", desc.Digest.String()).
			Msg("failed to read local blob for seeding")

		return false
	}
	defer blob.Close()

	// FullBlobUpload digest-verifies what it writes, so a corrupt or truncated
	// read fails here instead of ending up in the temp layout.
	if _, _, err := seeder.tempStore.FullBlobUpload(ctx, seeder.localRepo, blob, desc.Digest); err != nil {
		service.log.Debug().Err(err).Str("repo", seeder.localRepo).Str("digest", desc.Digest.String()).
			Msg("failed to seed local blob into temp sync dir")

		return false
	}

	seeder.seeded.Add(1)

	return true
}
