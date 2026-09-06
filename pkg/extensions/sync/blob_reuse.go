//go:build sync

package sync

import (
	"context"
	"io"
	"os"
	"path"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/ref"

	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// preseedLocalBlobs writes every blobDigests entry already present in localRepo's real local
// storage into localImageRef's temp OCI layout, at the exact path regclient's ocidir scheme
// checks before fetching a blob from upstream (blobs/<algo>/<encoded> under the ref's Path).
// regclient's own BlobCopy already skips the network fetch for a blob it finds at the copy
// target - this makes that skip actually fire for blobs zot's local store already has, instead
// of every sync re-downloading them into an always-empty temp directory (the root cause of
// https://github.com/project-zot/zot/issues/4386: pulling a second tag that shares layers with
// an already-synced one re-downloads those shared layers).
//
// A digest missing locally, or a CheckBlob/copy error, is simply skipped (fail open): preseeding
// is an optimization, never a correctness requirement, since ImageCopy fetches anything not
// pre-seeded on its own. Returns the number of blobs actually reused, for logging.
func (service *BaseService) preseedLocalBlobs(ctx context.Context, localRepo string,
	localImageRef ref.Ref, blobDigests []godigest.Digest,
) int {
	if localImageRef.Path == "" || len(blobDigests) == 0 {
		return 0
	}

	imageStore := service.storeController.GetImageStore(localRepo)

	seeded := 0

	for _, digest := range blobDigests {
		found, _, err := imageStore.CheckBlob(ctx, localRepo, digest)
		if err != nil || !found {
			continue
		}

		if err := preseedBlob(imageStore, localRepo, localImageRef, digest); err != nil {
			service.log.Warn().Err(err).Str("repo", localRepo).Str("digest", digest.String()).
				Msg("failed to reuse local blob, will fetch it from upstream instead")

			continue
		}

		seeded++
	}

	return seeded
}

// preseedBlob copies digest's content from imageStore into localImageRef's temp OCI layout.
func preseedBlob(imageStore storageTypes.ImageStore, localRepo string,
	localImageRef ref.Ref, digest godigest.Digest,
) error {
	destPath := path.Join(localImageRef.Path, "blobs", digest.Algorithm().String(), digest.Encoded())

	if _, err := os.Stat(destPath); err == nil {
		// already seeded, e.g. a layer digest that also appears as another manifest's config
		return nil
	}

	if err := os.MkdirAll(path.Dir(destPath), 0o755); err != nil {
		return err
	}

	src, _, err := imageStore.GetBlob(localRepo, digest, "")
	if err != nil {
		return err
	}
	defer src.Close()

	dest, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer dest.Close()

	_, err = io.Copy(dest, src)

	return err
}
