package ociutils

import (
	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zLog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	stypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func GetDefaultImageStore(rootDir string, log zLog.Logger) stypes.ImageStore {
	return local.NewImageStore(rootDir, false, false, log,
		monitoring.NewMetricsServer(false, log),
		mocks.MockedLint{
			LintFn: func(repo string, manifestDigest godigest.Digest, imageStore stypes.ImageStore) (bool, error) {
				return true, nil
			},
		},
		mocks.CacheMock{}, nil, nil,
	)
}

func GetDefaultStoreController(rootDir string, log zLog.Logger) stypes.StoreController {
	return storage.StoreController{
		DefaultStore: GetDefaultImageStore(rootDir, log),
	}
}
