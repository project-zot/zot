package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func getDigest(str string) string {
	return strings.Fields(str)[0]
}

func encryptFile(path string) string {
	output, _ := exec.Command("sha256sum", path).Output()
	return getDigest(string(output))
}

func getFileAttribute(name string, path string, imageName string) (string, string, int) {
	encryptName := encryptFile(path)
	err := renameFile(encryptName, name, imageName)
	if err != nil {
		log.Fatal(err)
	}
	filePath := fmt.Sprintf(pathFormat, imageName, encryptName)
	fileSize := getFileSize(filePath)

	return encryptName, filePath, fileSize
}

func makeImageDir(name string) error {
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

func renameFile(newName string, oldName string, imageName string) error {
	originalPath := fmt.Sprintf(pathFormat, imageName, oldName)
	newPath := fmt.Sprintf(pathFormat, imageName, newName)
	err := os.Rename(originalPath, newPath)

	return err
}

func getFileSize(path string) int {
	info, err := os.Stat(fmt.Sprintf(path))
	if err != nil {
		return -1
	}

	return int(info.Size())
}
