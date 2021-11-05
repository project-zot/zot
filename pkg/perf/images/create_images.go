package images

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func CreateImages(parallelImagesNumber int) error {
	pushedImages := GetImagesName()
	for i := 0; i < len(pushedImages); i++ {
		imageDir := fmt.Sprintf(imageDirPath, pushedImages[i])
		if _, err := os.Stat(imageDir); os.IsNotExist(err) {
			if err := MakeImageDir(imageDir); err != nil {
				return err
			}

			if err := CreateLayout(imageDir); err != nil {
				log.Fatalln(err)
			}

			manifestName, manifestSize := CreateBlobs(size, imageDir)
			CreateIndex(imageDir, manifestName, manifestSize)
		}
	}

	for i := 1; i <= parallelImagesNumber; i++ {
		imageDir := fmt.Sprintf(imageDirPath, fmt.Sprintf(parallelImagesName, i))
		if _, err := os.Stat(imageDir); os.IsNotExist(err) {
			if err := MakeImageDir(imageDir); err != nil {
				log.Fatalln(err)
			}

			if err := CreateLayout(imageDir); err != nil {
				log.Fatalln(err)
			}

			manifestName, manifestSize := CreateBlobs(i*size, imageDir)
			CreateIndex(imageDir, manifestName, manifestSize)
		}
	}

	return nil
}

func DeleteImages(parallelImagesNumber int) error {
	pushedImages := GetImagesName()
	for i := 0; i < len(pushedImages); i++ {
		if err := os.RemoveAll(fmt.Sprintf(imageDirPath, pushedImages[i])); err != nil {
			return err
		}
	}

	for i := 1; i <= parallelImagesNumber; i++ {
		if err := os.RemoveAll(fmt.Sprintf(imageDirPath, fmt.Sprintf(parallelImagesName, i))); err != nil {
			return err
		}
	}

	return nil
}

func CreateLayout(imageName string) error {
	data := ispec.ImageLayout{
		Version: ispec.ImageLayoutVersion,
	}

	file, err := json.MarshalIndent(data, "", " ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/%s", imageName, ispec.ImageLayoutFile), file, 0600)
	if err != nil {
		return err
	}

	return nil
}

func CreateBlobs(size int, imageName string) (string, int64) {
	// create blob
	filePath := fmt.Sprintf(pathFormat, imageName, filename)
	bigBuff := make([]byte, size)

	err := ioutil.WriteFile(filePath, bigBuff, 0600)
	if err != nil {
		log.Fatalln("Error creating file", err)
	}

	fileName, filePath, _ := GetFileAttribute(filename, filePath, imageName)

	// compress blob
	layerPath := fmt.Sprintf(pathFormat, imageName, tarName)
	filesList := []string{filePath}

	layer, err := os.Create(layerPath)
	if err != nil {
		log.Fatalln("Error writing archive", err)
	}

	err = CreateArchive(filesList, layer)
	if err != nil {
		log.Fatalln("Error creating archive", err)
	}

	layerName, _, layerSize :=
		GetFileAttribute(tarName, layerPath, imageName)

	// create config
	RootFS := ispec.RootFS{
		Type: "layers",
		DiffIDs: []godigest.Digest{
			godigest.Digest(fmt.Sprintf(digestFormat, fileName)),
		},
	}

	config := ispec.Image{
		Architecture: "amd64",
		OS:           "linux",
		RootFS:       RootFS,
	}

	configFile, _ := json.MarshalIndent(config, "", " ")
	configPath := fmt.Sprintf(pathFormat, imageName, configFileName)

	err = ioutil.WriteFile(configPath, configFile, 0600)
	if err != nil {
		log.Fatalln("Error creating config file", err)
	}

	configName, _, configSize := GetFileAttribute(configFileName, configPath, imageName)

	// create manifest
	annotationsMap := make(map[string]string)
	annotationsMap[ispec.AnnotationRefName] = "1.0"
	manifestConfig := ispec.Descriptor{
		MediaType:   "application/vnd.oci.image.config.v1+json",
		Digest:      godigest.Digest(fmt.Sprintf(digestFormat, configName)),
		Size:        configSize,
		Annotations: annotationsMap,
	}

	layersConfig := ispec.Descriptor{
		MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
		Digest:    godigest.Digest(fmt.Sprintf(digestFormat, layerName)),
		Size:      layerSize,
	}

	manifest := ispec.Manifest{
		Config: manifestConfig,
		Layers: []ispec.Descriptor{
			layersConfig,
		},
	}
	manifest.SchemaVersion = 2

	manifestFile, _ := json.MarshalIndent(manifest, "", " ")
	manifestPath := fmt.Sprintf(pathFormat, imageName, manifestFileName)

	err = ioutil.WriteFile(manifestPath, manifestFile, 0600)
	if err != nil {
		log.Fatalln("Error creating manifest file", err)
	}

	manifestName, _, manifestSize :=
		GetFileAttribute(manifestFileName, manifestPath, imageName)

	return manifestName, manifestSize
}

func CreateIndex(imageName string, manifestName string, manifestSize int64) {
	manifests := ispec.Descriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    godigest.Digest(fmt.Sprintf(digestFormat, manifestName)),
		Size:      manifestSize,
	}

	index := ispec.Index{
		Manifests: []ispec.Descriptor{
			manifests,
		},
	}
	index.SchemaVersion = 2

	indexFile, _ := json.MarshalIndent(index, "", " ")
	indexPath := path.Join(imageName, "index.json")

	err := ioutil.WriteFile(indexPath, indexFile, 0600)
	if err != nil {
		log.Fatalln("Error creating index file", err)
	}
}
