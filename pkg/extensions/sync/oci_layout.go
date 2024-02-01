//go:build sync
// +build sync

package sync

import (
	"fmt"
	"os"
	"path"

	"github.com/containers/image/v5/oci/layout"
	"github.com/containers/image/v5/types"
	"github.com/gofrs/uuid"

	"zotregistry.dev/zot/pkg/extensions/sync/constants"
	"zotregistry.dev/zot/pkg/storage"
	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
	"zotregistry.dev/zot/pkg/test/inject"
)

type OciLayoutStorageImpl struct {
	storeController storage.StoreController
	context         *types.SystemContext
}

func NewOciLayoutStorage(storeController storage.StoreController) OciLayoutStorage {
	context := &types.SystemContext{}
	// preserve compression
	context.OCIAcceptUncompressedLayers = true

	return OciLayoutStorageImpl{
		storeController: storeController,
		context:         context,
	}
}

func (oci OciLayoutStorageImpl) GetContext() *types.SystemContext {
	return oci.context
}

func (oci OciLayoutStorageImpl) GetImageReference(repo string, reference string) (types.ImageReference, error) {
	localImageStore := oci.storeController.GetImageStore(repo)
	tempSyncPath := path.Join(localImageStore.RootDir(), repo, constants.SyncBlobUploadDir)

	// create session folder
	uuid, err := uuid.NewV4()
	// hard to reach test case, injected error, see pkg/test/dev.go
	if err := inject.Error(err); err != nil {
		return nil, err
	}

	sessionRepoPath := path.Join(tempSyncPath, uuid.String())

	localRepo := path.Join(sessionRepoPath, repo)
	if err := os.MkdirAll(localRepo, storageConstants.DefaultDirPerms); err != nil {
		return nil, err
	}

	_, refIsDigest := parseReference(reference)

	if !refIsDigest {
		localRepo = fmt.Sprintf("%s:%s", localRepo, reference)
	}

	localImageRef, err := layout.ParseReference(localRepo)
	if err != nil {
		return nil, err
	}

	return localImageRef, nil
}
