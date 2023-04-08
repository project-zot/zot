package common

import (
	"strings"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func GetImageDirAndTag(imageName string) (string, string) {
	var imageDir string

	var imageTag string

	if strings.Contains(imageName, ":") {
		imageDir, imageTag, _ = strings.Cut(imageName, ":")
	} else {
		imageDir = imageName
	}

	return imageDir, imageTag
}

func GetImageDirAndDigest(imageName string) (string, string) {
	var imageDir string

	var imageDigest string

	if strings.Contains(imageName, "@") {
		imageDir, imageDigest, _ = strings.Cut(imageName, "@")
	} else {
		imageDir = imageName
	}

	return imageDir, imageDigest
}

// GetImageDirAndReference returns the repo, digest and isTag.
func GetImageDirAndReference(imageName string) (string, string, bool) {
	if strings.Contains(imageName, "@") {
		repo, digest := GetImageDirAndDigest(imageName)

		return repo, digest, false
	}

	repo, tag := GetImageDirAndTag(imageName)

	return repo, tag, true
}

// GetImageLastUpdated This method will return last updated timestamp.
// The Created timestamp is used, but if it is missing, look at the
// history field and, if provided, return the timestamp of last entry in history.
func GetImageLastUpdated(imageInfo ispec.Image) time.Time {
	timeStamp := imageInfo.Created

	if timeStamp != nil && !timeStamp.IsZero() {
		return *timeStamp
	}

	if len(imageInfo.History) > 0 {
		timeStamp = imageInfo.History[len(imageInfo.History)-1].Created
	}

	if timeStamp == nil {
		timeStamp = &time.Time{}
	}

	return *timeStamp
}
