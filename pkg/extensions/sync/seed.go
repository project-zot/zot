//go:build sync

package sync

import (
	"bytes"
	"context"
	"os"
	"path"
	"sync"
	"sync/atomic"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/ref"

	storageCommon "zotregistry.dev/zot/v2/pkg/storage/common"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
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
// blob present in the local store, reporting whether the complete subtree was
// seeded.
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

	if complete {
		complete = seeder.seedManifestBlob(ctx, man, digest)
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

	content, err := seeder.imageStore.GetBlobContent(seeder.localRepo, digest)
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

// seedManifestBlob writes the manifest itself into the temp layout. It must be
// called only when the whole subtree was seeded: ImageCopy skips a child
// subtree entirely once the child manifest exists on the copy target.
func (seeder *refSeeder) seedManifestBlob(ctx context.Context, man manifest.Manifest, digest godigest.Digest) bool {
	release := seeder.acquire()
	defer release()

	// the content is already in hand (possibly fetched upstream, where there is
	// no local file to hardlink); FullBlobUpload digest-verifies either way
	content, err := man.RawBody()
	if err == nil {
		_, _, err = seeder.tempStore.FullBlobUpload(ctx, seeder.localRepo, bytes.NewReader(content), digest)
	}

	if err != nil {
		seeder.service.log.Debug().Err(err).Str("repo", seeder.localRepo).Str("digest", digest.String()).
			Msg("failed to seed manifest blob into temp sync dir")

		return false
	}

	seeder.seeded.Add(1)

	return true
}

// seedBlob makes a blob from the local store available in the temp layout,
// preferably by hardlink, falling back to streaming a copy.
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

	found, _, err := seeder.imageStore.CheckBlob(ctx, seeder.localRepo, desc.Digest)
	if err != nil || !found {
		return false
	}

	blobPath := seeder.tempStore.BlobPath(seeder.localRepo, desc.Digest)
	if err := os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms); err != nil {
		service.log.Debug().Err(err).Str("dir", path.Dir(blobPath)).Msg("failed to create temp sync blobs dir")

		return false
	}

	// Fast path: hardlink the store blob into the temp layout, free when the
	// store shares a filesystem with the temp dir. On any error (S3-backed
	// store, EXDEV, EPERM, ...) fall back to streaming a copy. The link shares
	// the store blob's inode, so seeded blobs must never be modified in place;
	// zot only reads or unlinks stored blobs, and blob writes on both stores go
	// via tmp file + rename.
	if err := os.Link(seeder.imageStore.BlobPath(seeder.localRepo, desc.Digest), blobPath); err == nil {
		seeder.seeded.Add(1)

		return true
	}

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
