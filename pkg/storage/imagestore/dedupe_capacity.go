package imagestore

import (
	"context"
	"io"
	"time"

	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
)

// keepFullCopy replaces the unregistered copy at blobPath, which CheckBlob has just linked to
// the origin, with a full copy of the origin's content. It is used when the cache cannot track
// another copy of digest: an unregistered placeholder would lose its content when the origin
// is deleted, because the hand-off only considers the copies the cache lists.
//
// The copy is staged and verified without the store lock, which the caller holds and which is
// held again on return, so that a large copy does not block every repository. While the lock is
// released, a push or another CheckBlob can put a full copy at blobPath; once the lock is held
// again, such a copy is kept and the staged one dropped. Only a placeholder that is still
// without content is replaced, or removed when staging failed. writeLocked tells which kind of
// lock the caller holds, and the same kind is held again on return.
func (is *ImageStore) keepFullCopy(ctx context.Context, repo, blobPath, origin string, digest godigest.Digest,
	writeLocked bool, lockLatency *time.Time,
) error {
	if writeLocked {
		is.Unlock(lockLatency)
	} else {
		is.RUnlock(lockLatency)
	}

	staged, stageErr := is.stageVerifiedCopy(ctx, repo, origin, digest)

	if writeLocked {
		is.Lock(lockLatency)
	} else {
		is.RLock(lockLatency)
	}

	placeholder, err := is.isPlaceholderCopy(digest, blobPath)
	if err != nil {
		if staged != "" {
			_ = is.storeDriver.Delete(staged)
		}

		return err
	}

	if !placeholder {
		if staged != "" {
			_ = is.storeDriver.Delete(staged)
		}

		return nil
	}

	if stageErr != nil {
		_ = is.storeDriver.Delete(blobPath)

		return stageErr
	}

	if err := is.storeDriver.Move(staged, blobPath); err != nil {
		_ = is.storeDriver.Delete(staged)
		_ = is.storeDriver.Delete(blobPath)

		return err
	}

	return nil
}

// isPlaceholderCopy reports whether the copy at blobPath still has no content: it is a
// placeholder, or it is gone. A copy holding content, or a copy of the empty digest, is not
// one.
func (is *ImageStore) isPlaceholderCopy(digest godigest.Digest, blobPath string) (bool, error) {
	binfo, err := is.storeDriver.Stat(blobPath)
	if err != nil {
		if errclass.IsStorageObjectMissing(err) {
			return true, nil
		}

		return false, mapStorageErr(err)
	}

	return lacksContent(digest, binfo.Size()), nil
}

// stageVerifiedCopy copies the blob at src to a new upload path of repo, hashing the copy on
// the way, and returns that path once the copy matches digest. Otherwise it removes the copy.
func (is *ImageStore) stageVerifiedCopy(ctx context.Context, repo, src string, digest godigest.Digest,
) (string, error) {
	id, err := guuid.NewV4()
	if err != nil {
		return "", err
	}

	staged := is.BlobUploadPath(repo, id.String())

	err = func() error {
		reader, err := is.storeDriver.Reader(src, 0)
		if err != nil {
			return mapStorageErr(err)
		}

		defer reader.Close()

		writer, err := is.storeDriver.Writer(staged, false)
		if err != nil {
			return mapStorageErr(err)
		}

		digester := digest.Algorithm().Hash()

		if _, err := io.Copy(io.MultiWriter(writer, digester), &contextReader{ctx: ctx, reader: reader}); err != nil {
			_ = writer.Close()

			return err
		}

		if err := writer.Commit(ctx); err != nil {
			_ = writer.Close()

			return err
		}

		if err := writer.Close(); err != nil {
			return err
		}

		if godigest.NewDigest(digest.Algorithm(), digester) != digest {
			return zerr.ErrBadBlobDigest
		}

		return nil
	}()
	if err != nil {
		_ = is.storeDriver.Delete(staged)

		return "", err
	}

	return staged, nil
}

// contextReader stops a copy when its context is done.
type contextReader struct {
	ctx    context.Context //nolint:containedctx
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}

	return r.reader.Read(p)
}
