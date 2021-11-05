package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
)

func main() {
	for i, imageName := range imageNameList {
		if err := makeImageDir(imageName); err != nil {
			log.Fatal(err)
		}

		createLayout(imageName)
		manifestName, manifestSize := createBlobs(i*150000000, imageName)
		createIndex(imageName, manifestName, manifestSize)
	}
}

func createLayout(imageName string) {
	data := Layout{
		ImageLayoutVersion: "1.0.0",
	}

	file, _ := json.MarshalIndent(data, "", " ")
	_ = ioutil.WriteFile(fmt.Sprintf(layoutFormat, imageName), file, 0644)
}

func createBlobs(size int, imageName string) (string, int) {
	// create blob
	filePath := fmt.Sprintf(pathFormat, imageName, filename)
	bigBuff := make([]byte, size)

	err := ioutil.WriteFile(filePath, bigBuff, 0666)
	if err != nil {
		log.Fatalln("Error creating file", err)
	}

	fileName, filePath, _ := getFileAttribute(filename, filePath, imageName)

	// compress blob
	layerPath := fmt.Sprintf(pathFormat, imageName, tarName)
	filesList := []string{filePath}

	layer, err := os.Create(layerPath)
	if err != nil {
		log.Fatalln("Error writing archive", err)
	}

	err = createArchive(filesList, layer)
	if err != nil {
		log.Fatalln("Error creating archive", err)
	}

	layerName, _, layerSize :=
		getFileAttribute(tarName, layerPath, imageName)

	// create config
	RootFs := RootFs{
		Type: "layers",
		Diff_ids: []string{
			fmt.Sprintf(digestFormat, fileName),
		},
	}

	config := Config{
		Architecture: "amd64",
		Os:           "linux",
		Rootfs:       RootFs,
	}

	configFile, _ := json.MarshalIndent(config, "", " ")
	configPath := fmt.Sprintf(pathFormat, imageName, configFileName)

	err = ioutil.WriteFile(configPath, configFile, 0644)
	if err != nil {
		log.Fatalln("Error creating config file", err)
	}

	configName, configPath, configSize := getFileAttribute(configFileName, configPath, imageName)

	// create manifest
	manifestConfig := ManifestConfig{
		MediaType: "application/vnd.oci.image.config.v1+json",
		Digest:    fmt.Sprintf(digestFormat, configName),
		Size:      configSize,
	}

	layersConfig := ManifestConfig{
		MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
		Digest:    fmt.Sprintf(digestFormat, layerName),
		Size:      layerSize,
	}

	manifest := Manifest{
		SchemaVersion: 2,
		Config:        manifestConfig,
		Layers: []ManifestConfig{
			layersConfig,
		},
	}

	manifestFile, _ := json.MarshalIndent(manifest, "", " ")
	manifestPath := fmt.Sprintf(pathFormat, imageName, manifestFileName)

	err = ioutil.WriteFile(manifestPath, manifestFile, 0644)
	if err != nil {
		log.Fatalln("Error creating manifest file", err)
	}

	manifestName, _, manifestSize :=
		getFileAttribute(manifestFileName, manifestPath, imageName)

	return manifestName, manifestSize
}

func createIndex(imageName string, manifestName string, manifestSize int) {
	manifests := ManifestConfig{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    fmt.Sprintf(digestFormat, manifestName),
		Size:      manifestSize,
	}

	index := Index{
		SchemaVersion: 2,
		Manifests: []ManifestConfig{
			manifests,
		},
	}

	indexFile, _ := json.MarshalIndent(index, "", " ")
	indexPath := path.Join(imageName, "index.json")

	err := ioutil.WriteFile(indexPath, indexFile, 0644)
	if err != nil {
		log.Fatalln("Error creating index file", err)
	}
}
