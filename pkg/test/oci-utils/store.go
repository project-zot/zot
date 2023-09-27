package ociutils

import (
	godigest "github.com/opencontainers/go-digest"

	"zotregistry.io/zot/pkg/extensions/monitoring"
	zLog "zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	stypes "zotregistry.io/zot/pkg/storage/types"
	"zotregistry.io/zot/pkg/test/mocks"
)

func GetDefaultImageStore(rootDir string, log zLog.Logger) stypes.ImageStore {
	return local.NewImageStore(rootDir, false, false, log,
		monitoring.NewMetricsServer(false, log),
		mocks.MockedLint{
			LintFn: func(repo string, manifestDigest godigest.Digest, imageStore stypes.ImageStore) (bool, error) {
				return true, nil
			},
		},
		mocks.CacheMock{},
	)
}

func GetDefaultStoreController(rootDir string, log zLog.Logger) stypes.StoreController {
	return storage.StoreController{
		DefaultStore: GetDefaultImageStore(rootDir, log),
	}
}
