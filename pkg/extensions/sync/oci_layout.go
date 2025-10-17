//go:build sync
// +build sync

package sync

import (
	"fmt"
	"path"

	"github.com/gofrs/uuid"
	"github.com/regclient/regclient/types/ref"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/test/inject"
)

type OciLayoutStorageImpl struct {
	storeController storage.StoreController
}

func NewOciLayoutStorage(storeController storage.StoreController) OciLayoutStorage {
	return OciLayoutStorageImpl{
		storeController: storeController,
	}
}

func (oci OciLayoutStorageImpl) GetImageReference(repo string, reference string) (ref.Ref, error) {
	localImageStore := oci.storeController.GetImageStore(repo)
	if localImageStore == nil {
		return ref.Ref{}, zerr.ErrLocalImgStoreNotFound
	}

	tempSyncPath := path.Join(localImageStore.RootDir(), repo, constants.SyncBlobUploadDir)

	// create session folder
	uuid, err := uuid.NewV4()
	// hard to reach test case, injected error, see pkg/test/dev.go
	if err := inject.Error(err); err != nil {
		return ref.Ref{}, err
	}

	sessionRepoPath := path.Join(tempSyncPath, uuid.String())

	sessionRepo := path.Join(sessionRepoPath, repo)

	var imageRefPath string

	digest, ok := parseReference(reference)
	if ok {
		imageRefPath = fmt.Sprintf("ocidir://%s@%s", sessionRepo, digest.String())
	} else {
		imageRefPath = fmt.Sprintf("ocidir://%s:%s", sessionRepo, reference) //nolint: nosprintfhostport
	}

	imageReference, err := ref.New(imageRefPath)
	if err != nil {
		return ref.Ref{}, err
	}

	return imageReference, nil
}
