package image

import (
	"crypto/rand"
	"encoding/json"
	"log"
	"math/big"
	mathRand "math/rand"
	"os"
	"path/filepath"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	tcommon "zotregistry.dev/zot/pkg/test/common"
)

var vulnerableLayer []byte //nolint: gochecknoglobals

// These are the 3 vulnerabilities found for the returned image by the GetVulnImage function.
const (
	Vulnerability1ID = "CVE-2023-2650"
	Vulnerability2ID = "CVE-2023-1255"
	Vulnerability3ID = "CVE-2023-2975"
)

func GetLayerWithVulnerability() ([]byte, error) {
	if vulnerableLayer != nil {
		return vulnerableLayer, nil
	}
	// this is the path of the blob relative to the root of the zot folder
	vulnBlobPath := "test/data/alpine/blobs/sha256/f56be85fc22e46face30e2c3de3f7fe7c15f8fd7c4e5add29d7f64b87abdaa09"
	vulnerableLayer, err := GetLayerRelativeToProjectRoot(vulnBlobPath)

	return vulnerableLayer, err
}

func GetLayerWithLanguageFileVulnerability() ([]byte, error) {
	vulnBlobPath := "test/data/spring-web/blobs/sha256/506c47a6827e325a63d4b38c7ce656e07d5e98a09d748ec7ac989a45af7d6567"
	vulnerableLayerWithLanguageFile, err := GetLayerRelativeToProjectRoot(vulnBlobPath)

	return vulnerableLayerWithLanguageFile, err
}

func GetLayerRelativeToProjectRoot(pathToLayerBlob string) ([]byte, error) {
	projectRootDir, err := tcommon.GetProjectRootDir()
	if err != nil {
		return nil, err
	}

	absoluteBlobPath, _ := filepath.Abs(filepath.Join(projectRootDir, pathToLayerBlob))

	layer, err := os.ReadFile(absoluteBlobPath) //nolint: lll
	if err != nil {
		return nil, err
	}

	return layer, nil
}

func GetDefaultLayers() []Layer {
	return []Layer{
		{Blob: []byte("abc"), Digest: godigest.FromBytes([]byte("abc")), MediaType: ispec.MediaTypeImageLayerGzip},
		{Blob: []byte("123"), Digest: godigest.FromBytes([]byte("123")), MediaType: ispec.MediaTypeImageLayerGzip},
		{Blob: []byte("xyz"), Digest: godigest.FromBytes([]byte("xyz")), MediaType: ispec.MediaTypeImageLayerGzip},
	}
}

func GetDefaultLayersBlobs() [][]byte {
	return [][]byte{
		[]byte("abc"),
		[]byte("123"),
		[]byte("xyz"),
	}
}

func GetDefaultConfig() ispec.Image {
	return ispec.Image{
		Created: DefaultTimeRef(),
		Author:  "ZotUser",
		Platform: ispec.Platform{
			OS:           "linux",
			Architecture: "amd64",
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{},
		},
	}
}

func DefaultTimeRef() *time.Time {
	var (
		year  = 2010
		month = time.Month(1)
		day   = 1
		hour  = 1
		min   = 1
		sec   = 1
		nsec  = 0
	)

	return DateRef(year, month, day, hour, min, sec, nsec, time.UTC)
}

func DateRef(year int, month time.Month, day, hour, min, sec, nsec int, loc *time.Location) *time.Time {
	date := time.Date(year, month, day, hour, min, sec, nsec, loc)

	return &date
}

func RandomDateRef(loc *time.Location) *time.Time {
	var (
		year  = 1990 + mathRand.Intn(30)          //nolint: gosec,gomnd
		month = time.Month(1 + mathRand.Intn(10)) //nolint: gosec,gomnd
		day   = 1 + mathRand.Intn(5)              //nolint: gosec,gomnd
		hour  = 1 + mathRand.Intn(22)             //nolint: gosec,gomnd
		min   = 1 + mathRand.Intn(58)             //nolint: gosec,gomnd
		sec   = 1 + mathRand.Intn(58)             //nolint: gosec,gomnd
		nsec  = 1
	)

	return DateRef(year, month, day, hour, min, sec, nsec, time.UTC)
}

func GetDefaultVulnConfig() ispec.Image {
	return ispec.Image{
		Created: DefaultTimeRef(),
		Author:  "ZotUser",
		Platform: ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		Config: ispec.ImageConfig{
			Env: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
			Cmd: []string{"/bin/sh"},
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{"sha256:f1417ff83b319fbdae6dd9cd6d8c9c88002dcd75ecf6ec201c8c6894681cf2b5"},
		},
	}
}

// Adapted from https://gist.github.com/dopey/c69559607800d2f2f90b1b1ed4e550fb
func RandomString(n int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

	ret := make([]byte, n)

	for count := 0; count < n; count++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(err)
		}

		ret[count] = letters[num.Int64()]
	}

	return string(ret)
}

func GetRandomImageConfig() ([]byte, godigest.Digest) {
	const maxLen = 16

	randomAuthor := RandomString(maxLen)

	config := ispec.Image{
		Platform: ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{},
		},
		Author: randomAuthor,
	}

	configBlobContent, err := json.MarshalIndent(&config, "", "\t")
	if err != nil {
		log.Fatal(err)
	}

	configBlobDigestRaw := godigest.FromBytes(configBlobContent)

	return configBlobContent, configBlobDigestRaw
}
