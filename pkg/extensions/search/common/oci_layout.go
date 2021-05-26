// Package common ...
package common

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// CveInfo ...
type OciLayoutUtils struct {
	Log             log.Logger
	StoreController storage.StoreController
}

// NewOciLayoutUtils initializes a new OciLayoutUtils object.
func NewOciLayoutUtils(storeController storage.StoreController, log log.Logger) *OciLayoutUtils {
	return &OciLayoutUtils{Log: log, StoreController: storeController}
}

// Below method will return image path including root dir, root dir is determined by splitting.
func (olu OciLayoutUtils) GetImageRepoPath(image string) string {
	var rootDir string

	prefixName := GetRoutePrefix(image)

	subStore := olu.StoreController.SubStore

	if subStore != nil {
		imgStore, ok := olu.StoreController.SubStore[prefixName]
		if ok {
			rootDir = imgStore.RootDir()
		} else {
			rootDir = olu.StoreController.DefaultStore.RootDir()
		}
	} else {
		rootDir = olu.StoreController.DefaultStore.RootDir()
	}

	return path.Join(rootDir, image)
}

func (olu OciLayoutUtils) GetImageManifests(imagePath string) ([]ispec.Descriptor, error) {
	buf, err := ioutil.ReadFile(path.Join(imagePath, "index.json"))

	if err != nil {
		if os.IsNotExist(err) {
			olu.Log.Error().Err(err).Msg("index.json doesn't exist")

			return nil, errors.ErrRepoNotFound
		}

		olu.Log.Error().Err(err).Msg("unable to open index.json")

		return nil, errors.ErrRepoNotFound
	}

	var index ispec.Index

	if err := json.Unmarshal(buf, &index); err != nil {
		olu.Log.Error().Err(err).Str("dir", imagePath).Msg("invalid JSON")
		return nil, errors.ErrRepoNotFound
	}

	return index.Manifests, nil
}

func (olu OciLayoutUtils) GetImageBlobManifest(imageDir string, digest godigest.Digest) (v1.Manifest, error) {
	var blobIndex v1.Manifest

	blobBuf, err := ioutil.ReadFile(path.Join(imageDir, "blobs", digest.Algorithm().String(), digest.Encoded()))
	if err != nil {
		olu.Log.Error().Err(err).Msg("unable to open image metadata file")

		return blobIndex, err
	}

	if err := json.Unmarshal(blobBuf, &blobIndex); err != nil {
		olu.Log.Error().Err(err).Msg("unable to marshal blob index")

		return blobIndex, err
	}

	return blobIndex, nil
}

func (olu OciLayoutUtils) GetImageInfo(imageDir string, hash v1.Hash) (ispec.Image, error) {
	var imageInfo ispec.Image

	blobBuf, err := ioutil.ReadFile(path.Join(imageDir, "blobs", hash.Algorithm, hash.Hex))
	if err != nil {
		olu.Log.Error().Err(err).Msg("unable to open image layers file")

		return imageInfo, err
	}

	if err := json.Unmarshal(blobBuf, &imageInfo); err != nil {
		olu.Log.Error().Err(err).Msg("unable to marshal blob index")

		return imageInfo, err
	}

	return imageInfo, err
}

func GetRoutePrefix(name string) string {
	names := strings.SplitN(name, "/", 2)

	if len(names) != 2 { // nolint: gomnd
		// it means route is of global storage e.g "centos:latest"
		if len(names) == 1 {
			return "/"
		}
	}

	return fmt.Sprintf("/%s", names[0])
}

func DirExists(d string) bool {
	fi, err := os.Stat(d)
	if err != nil && os.IsNotExist(err) {
		return false
	}

	return fi.IsDir()
}

func GetImageDirAndTag(imageName string) (string, string) {
	var imageDir string

	var imageTag string

	if strings.Contains(imageName, ":") {
		splitImageName := strings.Split(imageName, ":")
		imageDir = splitImageName[0]
		imageTag = splitImageName[1]
	} else {
		imageDir = imageName
	}

	return imageDir, imageTag
}
