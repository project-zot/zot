package image

import (
	mathRand "math/rand"
	"os"
	"path/filepath"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	testc "zotregistry.io/zot/pkg/test/common"
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

	projectRootDir, err := testc.GetProjectRootDir()
	if err != nil {
		return nil, err
	}

	// this is the path of the blob relative to the root of the zot folder
	vulnBlobPath := "test/data/alpine/blobs/sha256/f56be85fc22e46face30e2c3de3f7fe7c15f8fd7c4e5add29d7f64b87abdaa09"

	absoluteVulnBlobPath, _ := filepath.Abs(filepath.Join(projectRootDir, vulnBlobPath))

	vulnerableLayer, err := os.ReadFile(absoluteVulnBlobPath) //nolint: lll
	if err != nil {
		return nil, err
	}

	return vulnerableLayer, nil
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
