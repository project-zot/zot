package storage

import (
	"strings"

	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

const (
	CosignType       = "cosign"
	NotationType     = "notation"
	DefaultStorePath = "/"
)

type StoreController struct {
	DefaultStore storageTypes.ImageStore
	SubStore     map[string]storageTypes.ImageStore
	// SyncDownloadDir is extensions.sync.downloadDir when set at init. On-demand sync staging
	// for all stores (including remote-backed ones) lives under this directory.
	SyncDownloadDir string
}

func GetRoutePrefix(name string) string {
	names := strings.SplitN(name, "/", 2) //nolint:mnd

	if len(names) != 2 { //nolint:mnd
		// it means route is of global storage e.g "centos:latest"
		if len(names) == 1 {
			return "/"
		}
	}

	return "/" + names[0]
}

func (sc StoreController) GetStorePath(name string) string {
	if sc.SubStore != nil && name != "" {
		subStorePath := GetRoutePrefix(name)

		_, ok := sc.SubStore[subStorePath]
		if !ok {
			return DefaultStorePath
		}

		return subStorePath
	}

	return DefaultStorePath
}

func (sc StoreController) GetImageStore(name string) storageTypes.ImageStore {
	if sc.SubStore != nil {
		// SubStore is being provided, now we need to find equivalent image store and this will be found by splitting name
		prefixName := GetRoutePrefix(name)

		imgStore, ok := sc.SubStore[prefixName]
		if !ok {
			imgStore = sc.DefaultStore
		}

		return imgStore
	}

	return sc.DefaultStore
}

func (sc StoreController) GetDefaultImageStore() storageTypes.ImageStore {
	return sc.DefaultStore
}

func (sc StoreController) GetImageSubStores() map[string]storageTypes.ImageStore {
	return sc.SubStore
}

// SyncStagingRootForImageStore returns the local filesystem root where on-demand sync staging
// for repos in this image store may exist. When SyncDownloadDir is set, staging always lives
// there (including for remote serving stores). Otherwise it is the store RootDir for local
// drivers. An empty return means this store has no local staging to guard.
func (sc StoreController) SyncStagingRootForImageStore(imgStore storageTypes.ImageStore) string {
	if sc.SyncDownloadDir != "" {
		return sc.SyncDownloadDir
	}

	if imgStore == nil || imgStore.Name() != storageConstants.LocalStorageDriverName {
		return ""
	}

	return imgStore.RootDir()
}

// SyncStagingRootForRepo returns the staging root for the image store that serves repo.
func (sc StoreController) SyncStagingRootForRepo(repo string) string {
	return sc.SyncStagingRootForImageStore(sc.GetImageStore(repo))
}

// SyncStagingRoots returns local filesystem roots that may contain on-demand sync staging
// sessions under <repo>/.sync/<uuid>/.
func (sc StoreController) SyncStagingRoots() []string {
	if sc.SyncDownloadDir != "" {
		return []string{sc.SyncDownloadDir}
	}

	seen := make(map[string]struct{})
	roots := make([]string, 0)

	add := func(imgStore storageTypes.ImageStore) {
		root := sc.SyncStagingRootForImageStore(imgStore)
		if root == "" {
			return
		}

		if _, ok := seen[root]; ok {
			return
		}

		seen[root] = struct{}{}
		roots = append(roots, root)
	}

	add(sc.DefaultStore)

	for _, imgStore := range sc.SubStore {
		add(imgStore)
	}

	return roots
}
