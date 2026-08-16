package image

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	stypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

const manifestVisibilityPollInterval = 100 * time.Millisecond

func waitForManifest(store stypes.ImageStore, repoName, ref string) error {
	for range 100 {
		_, _, _, err := store.GetImageManifest(repoName, ref) //nolint:dogsled // Only readiness matters here.
		if err == nil {
			return nil
		}

		if !errors.Is(err, zerr.ErrManifestNotFound) && !errors.Is(err, zerr.ErrRepoNotFound) {
			return err
		}

		// Remote storage emulators may expose the updated repository index after the write returns.
		time.Sleep(manifestVisibilityPollInterval)
	}

	_, _, _, err := store.GetImageManifest(repoName, ref) //nolint:dogsled // Return the final readiness error.

	return err
}

func WriteImageToFileSystem(image Image, repoName, ref string, storeController stypes.StoreController) error {
	store := storeController.GetImageStore(repoName)

	err := store.InitRepo(context.Background(), repoName)
	if err != nil {
		return err
	}

	digestAlgorithm := image.digestAlgorithm

	if digestAlgorithm == "" {
		digestAlgorithm = godigest.Canonical
	}

	for _, layerBlob := range image.Layers {
		layerReader := bytes.NewReader(layerBlob)
		layerDigest := digestAlgorithm.FromBytes(layerBlob)

		_, _, err = store.FullBlobUpload(context.Background(), repoName, layerReader, layerDigest)
		if err != nil {
			return err
		}
	}

	configBlob, err := json.Marshal(image.Config)
	if err != nil {
		return err
	}

	configReader := bytes.NewReader(configBlob)
	configDigest := digestAlgorithm.FromBytes(configBlob)

	_, _, err = store.FullBlobUpload(context.Background(), repoName, configReader, configDigest)
	if err != nil {
		return err
	}

	manifestBlob, err := json.Marshal(image.Manifest)
	if err != nil {
		return err
	}

	_, _, err = store.PutImageManifest(context.Background(), repoName, ref, image.Manifest.MediaType, manifestBlob, nil)
	if err != nil {
		return err
	}

	return waitForManifest(store, repoName, ref)
}

func WriteMultiArchImageToFileSystem(multiarchImage MultiarchImage, repoName, ref string,
	storeController stypes.StoreController,
) error {
	store := storeController.GetImageStore(repoName)

	err := store.InitRepo(context.Background(), repoName)
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

	_, _, err = store.PutImageManifest(context.Background(), repoName, ref, multiarchImage.Index.MediaType,
		indexBlob, nil)
	if err != nil {
		return err
	}

	return waitForManifest(store, repoName, ref)
}
