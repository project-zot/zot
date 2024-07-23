package common

import (
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/errors"
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

func GetManifestArtifactType(manifestContent ispec.Manifest) string {
	if manifestContent.ArtifactType != "" {
		return manifestContent.ArtifactType
	}

	return manifestContent.Config.MediaType
}

func GetIndexArtifactType(indexContent ispec.Index) string {
	return indexContent.ArtifactType
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

// GetRepoReference returns the components of a repoName:tag or repoName@digest string. If the format is wrong
// an error is returned.
// The returned values have the following meaning:
//
// - string: repo name
//
// - string: reference (tag or digest)
//
// - bool: value for the statement: "the reference is a tag"
//
// - error: error value.
func GetRepoReference(repo string) (string, string, bool, error) {
	repoName, digest, found := strings.Cut(repo, "@")

	if !found {
		repoName, tag, found := strings.Cut(repo, ":")

		if !found {
			return "", "", false, zerr.ErrInvalidRepoRefFormat
		}

		return repoName, tag, true, nil
	}

	return repoName, digest, false, nil
}

// GetFullImageName returns the formatted string for the given repo/tag or repo/digest.
func GetFullImageName(repo, ref string) string {
	if IsTag(ref) {
		return repo + ":" + ref
	}

	return repo + "@" + ref
}

func IsDigest(ref string) bool {
	_, err := digest.Parse(ref)

	return err == nil
}

func IsTag(ref string) bool {
	return !IsDigest(ref)
}

func CheckIsCorrectRepoNameFormat(repo string) bool {
	return !strings.ContainsAny(repo, ":@")
}
