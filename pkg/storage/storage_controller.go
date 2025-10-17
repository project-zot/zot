package storage

import (
	"strings"

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
