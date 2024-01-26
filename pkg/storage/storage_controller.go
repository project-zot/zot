package storage

import (
	"fmt"
	"strings"

	storageTypes "zotregistry.dev/zot/pkg/storage/types"
)

const (
	CosignType   = "cosign"
	NotationType = "notation"
)

type StoreController struct {
	DefaultStore storageTypes.ImageStore
	SubStore     map[string]storageTypes.ImageStore
}

func GetRoutePrefix(name string) string {
	names := strings.SplitN(name, "/", 2) //nolint:gomnd

	if len(names) != 2 { //nolint:gomnd
		// it means route is of global storage e.g "centos:latest"
		if len(names) == 1 {
			return "/"
		}
	}

	return fmt.Sprintf("/%s", names[0])
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
