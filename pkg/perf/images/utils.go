package images

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

const (
	configFileName     = "configFile"
	digestFormat       = "sha256:%s"
	filename           = "file"
	imageDirPath       = "images/%s"
	manifestFileName   = "manifestFile"
	pathFormat         = "%s/blobs/sha256/%s"
	size               = 150000000
	tarName            = "file.tar.gz"
	parallelImagesName = "zot-tests-parallel-images-dummy-%d"
)

func GetImagesName() []string {
	return []string{"zot-tests-dummy-push", "zot-tests-single-images-dummy"}
}

func GetFileDigest(path string) string {
	body, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("Unable to read file: %v", err)
	}

	return fmt.Sprintf("%x", sha256.Sum256(body))
}

func GetFileAttribute(name string, path string, imageName string) (string, string, int64) {
	digestName := GetFileDigest(path)

	err := RenameFile(digestName, name, imageName)
	if err != nil {
		log.Fatal(err)
	}

	filePath := fmt.Sprintf(pathFormat, imageName, digestName)
	fileSize := GetFileSize(filePath)

	return digestName, filePath, fileSize
}

func MakeImageDir(name string) error {
	path := fmt.Sprintf("%s/blobs/sha256", name)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		log.Panic("Dir exists")
	}

	err := os.MkdirAll(path, 0777)
	if err != nil {
		return err
	}

	return nil
}

func RenameFile(newName string, oldName string, imageName string) error {
	originalPath := fmt.Sprintf(pathFormat, imageName, oldName)
	newPath := fmt.Sprintf(pathFormat, imageName, newName)
	err := os.Rename(originalPath, newPath)

	return err
}

func GetFileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return -1
	}

	return info.Size()
}
