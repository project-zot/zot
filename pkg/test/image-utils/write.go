package image

import (
	"bytes"
	"encoding/json"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	stypes "zotregistry.dev/zot/pkg/storage/types"
)

func WriteImageToFileSystem(image Image, repoName, ref string, storeController stypes.StoreController) error {
	store := storeController.GetImageStore(repoName)

	err := store.InitRepo(repoName)
	if err != nil {
		return err
	}

	for _, layerBlob := range image.Layers {
		layerReader := bytes.NewReader(layerBlob)
		layerDigest := godigest.FromBytes(layerBlob)

		_, _, err = store.FullBlobUpload(repoName, layerReader, layerDigest)
		if err != nil {
			return err
		}
	}

	configBlob, err := json.Marshal(image.Config)
	if err != nil {
		return err
	}

	configReader := bytes.NewReader(configBlob)
	configDigest := godigest.FromBytes(configBlob)

	_, _, err = store.FullBlobUpload(repoName, configReader, configDigest)
	if err != nil {
		return err
	}

	manifestBlob, err := json.Marshal(image.Manifest)
	if err != nil {
		return err
	}

	_, _, err = store.PutImageManifest(repoName, ref, ispec.MediaTypeImageManifest, manifestBlob)
	if err != nil {
		return err
	}

	return nil
}

func WriteMultiArchImageToFileSystem(multiarchImage MultiarchImage, repoName, ref string,
	storeController stypes.StoreController,
) error {
	store := storeController.GetImageStore(repoName)

	err := store.InitRepo(repoName)
	if err != nil {
		return err
	}

	for _, image := range multiarchImage.Images {
		err := WriteImageToFileSystem(image, repoName, image.DigestStr(), storeController)
		if err != nil {
			return err
		}
	}

	indexBlob, err := json.Marshal(multiarchImage.Index)
	if err != nil {
		return err
	}

	_, _, err = store.PutImageManifest(repoName, ref, ispec.MediaTypeImageIndex,
		indexBlob)

	return err
}
