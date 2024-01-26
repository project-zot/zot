package ociutils

import (
	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/pkg/extensions/monitoring"
	zLog "zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/local"
	stypes "zotregistry.dev/zot/pkg/storage/types"
	"zotregistry.dev/zot/pkg/test/mocks"
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
