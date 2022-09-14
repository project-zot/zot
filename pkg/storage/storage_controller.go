package storage

import (
	"fmt"
	"strings"

	"zotregistry.io/zot/pkg/metadata"
)

type StoreController struct {
	DefaultStore  ImageStore
	SubStore      map[string]ImageStore
	MetadataStore metadata.Store
}

// BlobUpload models and upload request.
type BlobUpload struct {
	StoreName string
	ID        string
}

func getRoutePrefix(name string) string {
	names := strings.SplitN(name, "/", 2) //nolint:gomnd

	if len(names) != 2 { //nolint:gomnd
		// it means route is of global storage e.g "centos:latest"
		if len(names) == 1 {
			return "/"
		}
	}

	return fmt.Sprintf("/%s", names[0])
}

func (sc StoreController) GetImageStore(name string) ImageStore {
	if sc.SubStore != nil {
		// SubStore is being provided, now we need to find equivalent image store and this will be found by splitting name
		prefixName := getRoutePrefix(name)

		imgStore, ok := sc.SubStore[prefixName]
		if !ok {
			imgStore = sc.DefaultStore
		}

		return imgStore
	}

	return sc.DefaultStore
}
