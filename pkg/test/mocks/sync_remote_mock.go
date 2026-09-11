package mocks

import (
	"context"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/ref"
)

type SyncRemoteMock struct {
	// Methods required by sync Remote interface.
	GetHostNameFn       func() string
	GetRepositoriesFn   func(ctx context.Context) ([]string, error)
	GetTagsFn           func(ctx context.Context, repo string) ([]string, error)
	HeadManifestFn      func(ctx context.Context, repo, tag string) (digest.Digest, string, error)
	HeadManifestRefFn   func(ctx context.Context, imageReference ref.Ref) (digest.Digest, string, error)
	GetManifestListFn   func(ctx context.Context, repo, reference string) ([]descriptor.Descriptor, error)
	GetImageReferenceFn func(repo string, tag string) (ref.Ref, error)
}

// Methods required by sync Remote interface.

func (remote SyncRemoteMock) GetHostName() string {
	if remote.GetHostNameFn != nil {
		return remote.GetHostNameFn()
	}

	return "mock-host"
}

func (remote SyncRemoteMock) GetRepositories(ctx context.Context) ([]string, error) {
	if remote.GetRepositoriesFn != nil {
		return remote.GetRepositoriesFn(ctx)
	}

	return []string{}, nil
}

func (remote SyncRemoteMock) GetTags(ctx context.Context, repo string) ([]string, error) {
	if remote.GetTagsFn != nil {
		return remote.GetTagsFn(ctx, repo)
	}

	return []string{}, nil
}

func (remote SyncRemoteMock) HeadManifest(ctx context.Context, repo, tag string) (digest.Digest, string, error) {
	if remote.HeadManifestFn != nil {
		return remote.HeadManifestFn(ctx, repo, tag)
	}

	return digest.Digest("sha256:abc123"), v1.MediaTypeImageManifest, nil
}

func (remote SyncRemoteMock) HeadManifestRef(ctx context.Context, imageReference ref.Ref,
) (digest.Digest, string, error) {
	if remote.HeadManifestRefFn != nil {
		return remote.HeadManifestRefFn(ctx, imageReference)
	}

	// Fall back so existing tests that only stub HeadManifestFn keep working.
	if remote.HeadManifestFn != nil {
		reference := imageReference.Digest
		if reference == "" {
			reference = imageReference.Tag
		}

		return remote.HeadManifestFn(ctx, imageReference.Repository, reference)
	}

	return digest.Digest("sha256:abc123"), v1.MediaTypeImageManifest, nil
}

func (remote SyncRemoteMock) GetManifestList(ctx context.Context, repo, reference string,
) ([]descriptor.Descriptor, error) {
	if remote.GetManifestListFn != nil {
		return remote.GetManifestListFn(ctx, repo, reference)
	}

	return nil, nil
}

func (remote SyncRemoteMock) GetImageReference(repo string, tag string) (ref.Ref, error) {
	if remote.GetImageReferenceFn != nil {
		return remote.GetImageReferenceFn(repo, tag)
	}

	return ref.New("mock-registry/" + repo + ":" + tag)
}

type SyncDestinationMock struct {
	// Methods required by sync Destination interface.
	GetImageReferenceFn func(repo string, tag string) (ref.Ref, error)
	CanSkipImageFn      func(repo string, tag string, digest digest.Digest) (bool, error)
	CommitAllFn         func(repo string, imageReference ref.Ref) error
	CleanupImageFn      func(imageReference ref.Ref, repo string) error
}

// Methods required by sync Destination interface.

func (dest SyncDestinationMock) GetImageReference(repo string, tag string) (ref.Ref, error) {
	if dest.GetImageReferenceFn != nil {
		return dest.GetImageReferenceFn(repo, tag)
	}

	return ref.New("mock-local/" + repo + ":" + tag)
}

func (dest SyncDestinationMock) CanSkipImage(repo string, tag string, digest digest.Digest) (bool, error) {
	if dest.CanSkipImageFn != nil {
		return dest.CanSkipImageFn(repo, tag, digest)
	}

	return false, nil
}

func (dest SyncDestinationMock) CommitAll(repo string, imageReference ref.Ref) error {
	if dest.CommitAllFn != nil {
		return dest.CommitAllFn(repo, imageReference)
	}

	return nil
}

func (dest SyncDestinationMock) CleanupImage(imageReference ref.Ref, repo string) error {
	if dest.CleanupImageFn != nil {
		return dest.CleanupImageFn(imageReference, repo)
	}

	return nil
}
