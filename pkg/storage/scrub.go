package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/umoci"
	"github.com/opencontainers/umoci/oci/casext"

	"zotregistry.io/zot/errors"
)

const (
	colImageNameIndex = iota
	colTagIndex
	colStatusIndex
	colErrorIndex

	imageNameWidth = 32
	tagWidth       = 24
	statusWidth    = 8
	errorWidth     = 8
)

type ScrubImageResult struct {
	ImageName string `json:"imageName"`
	Tag       string `json:"tag"`
	Status    string `json:"status"`
	Error     string `json:"error"`
}

type ScrubResults struct {
	ScrubResults []ScrubImageResult `json:"scrubResults"`
}

func (sc StoreController) CheckAllBlobsIntegrity() (ScrubResults, error) {
	results := ScrubResults{}

	imageStoreList := make(map[string]ImageStore)
	if sc.SubStore != nil {
		imageStoreList = sc.SubStore
	}

	imageStoreList[""] = sc.DefaultStore

	for _, imgStore := range imageStoreList {
		imgStoreResults, err := CheckImageStoreBlobsIntegrity(imgStore)
		if err != nil {
			return results, err
		}

		results.ScrubResults = append(results.ScrubResults, imgStoreResults...)
	}

	return results, nil
}

func CheckImageStoreBlobsIntegrity(imgStore ImageStore) ([]ScrubImageResult, error) {
	results := []ScrubImageResult{}

	repos, err := imgStore.GetRepositories()
	if err != nil {
		return results, err
	}

	for _, repo := range repos {
		imageResults, err := CheckRepo(repo, imgStore)
		if err != nil {
			return results, err
		}

		results = append(results, imageResults...)
	}

	return results, nil
}

func CheckRepo(imageName string, imgStore ImageStore) ([]ScrubImageResult, error) {
	results := []ScrubImageResult{}

	dir := path.Join(imgStore.RootDir(), imageName)
	if !imgStore.DirExists(dir) {
		return results, errors.ErrRepoNotFound
	}

	ctxUmoci := context.Background()

	oci, err := umoci.OpenLayout(dir)
	if err != nil {
		return results, err
	}
	defer oci.Close()

	var lockLatency time.Time

	imgStore.RLock(&lockLatency)
	defer imgStore.RUnlock(&lockLatency)

	buf, err := os.ReadFile(path.Join(dir, "index.json"))
	if err != nil {
		return results, err
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		return results, errors.ErrRepoNotFound
	}

	listOfManifests := []ispec.Descriptor{}

	for _, manifest := range index.Manifests {
		if manifest.MediaType == ispec.MediaTypeImageIndex {
			buf, err := os.ReadFile(path.Join(dir, "blobs", manifest.Digest.Algorithm().String(), manifest.Digest.Encoded()))
			if err != nil {
				tagName := manifest.Annotations[ispec.AnnotationRefName]
				imgRes := getResult(imageName, tagName, errors.ErrBadBlobDigest)
				results = append(results, imgRes)

				continue
			}

			var idx ispec.Index
			if err := json.Unmarshal(buf, &idx); err != nil {
				tagName := manifest.Annotations[ispec.AnnotationRefName]
				imgRes := getResult(imageName, tagName, errors.ErrBadBlobDigest)
				results = append(results, imgRes)

				continue
			}

			listOfManifests = append(listOfManifests, idx.Manifests...)
		} else if manifest.MediaType == ispec.MediaTypeImageManifest {
			listOfManifests = append(listOfManifests, manifest)
		}
	}

	for _, m := range listOfManifests {
		tag := m.Annotations[ispec.AnnotationRefName]
		imageResult := CheckIntegrity(ctxUmoci, imageName, tag, oci, m, dir)
		results = append(results, imageResult)
	}

	return results, nil
}

func CheckIntegrity(ctx context.Context, imageName, tagName string, oci casext.Engine, manifest ispec.Descriptor, dir string) ScrubImageResult { //nolint: lll
	// check manifest and config
	if _, err := umoci.Stat(ctx, oci, manifest); err != nil {
		return getResult(imageName, tagName, err)
	}

	// check layers
	return CheckLayers(imageName, tagName, dir, manifest)
}

func CheckLayers(imageName, tagName, dir string, manifest ispec.Descriptor) ScrubImageResult {
	imageRes := ScrubImageResult{}

	buf, err := os.ReadFile(path.Join(dir, "blobs", manifest.Digest.Algorithm().String(), manifest.Digest.Encoded()))
	if err != nil {
		imageRes = getResult(imageName, tagName, err)

		return imageRes
	}

	var man ispec.Manifest
	if err := json.Unmarshal(buf, &man); err != nil {
		imageRes = getResult(imageName, tagName, err)

		return imageRes
	}

	for _, layer := range man.Layers {
		layerPath := path.Join(dir, "blobs", layer.Digest.Algorithm().String(), layer.Digest.Encoded())

		_, err = os.Stat(layerPath)
		if err != nil {
			imageRes = getResult(imageName, tagName, errors.ErrBlobNotFound)

			break
		}

		layerFh, err := os.Open(layerPath)
		if err != nil {
			imageRes = getResult(imageName, tagName, errors.ErrBlobNotFound)

			break
		}

		computedDigest, err := godigest.FromReader(layerFh)
		layerFh.Close()

		if err != nil {
			imageRes = getResult(imageName, tagName, errors.ErrBadBlobDigest)

			break
		}

		if computedDigest != layer.Digest {
			imageRes = getResult(imageName, tagName, errors.ErrBadBlobDigest)

			break
		}

		imageRes = getResult(imageName, tagName, nil)
	}

	return imageRes
}

func getResult(imageName, tag string, err error) ScrubImageResult {
	var status string

	var errField string

	if err != nil {
		status = "affected"
		errField = err.Error()
	} else {
		status = "ok"
		errField = ""
	}

	return ScrubImageResult{
		ImageName: imageName,
		Tag:       tag,
		Status:    status,
		Error:     errField,
	}
}

func getScrubTableWriter(writer io.Writer) *tablewriter.Table {
	table := tablewriter.NewWriter(writer)

	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)
	table.SetColMinWidth(colImageNameIndex, imageNameWidth)
	table.SetColMinWidth(colTagIndex, tagWidth)
	table.SetColMinWidth(colStatusIndex, statusWidth)
	table.SetColMinWidth(colErrorIndex, errorWidth)

	return table
}

const tableCols = 4

func printScrubTableHeader(writer io.Writer) {
	table := getScrubTableWriter(writer)

	row := make([]string, tableCols)

	row[colImageNameIndex] = "IMAGE NAME"
	row[colTagIndex] = "TAG"
	row[colStatusIndex] = "STATUS"
	row[colErrorIndex] = "ERROR"

	table.Append(row)
	table.Render()
}

func printImageResult(imageResult ScrubImageResult) string {
	var builder strings.Builder

	table := getScrubTableWriter(&builder)
	table.SetColMinWidth(colImageNameIndex, imageNameWidth)
	table.SetColMinWidth(colTagIndex, tagWidth)
	table.SetColMinWidth(colStatusIndex, statusWidth)
	table.SetColMinWidth(colErrorIndex, errorWidth)

	row := make([]string, tableCols)

	row[colImageNameIndex] = imageResult.ImageName
	row[colTagIndex] = imageResult.Tag
	row[colStatusIndex] = imageResult.Status
	row[colErrorIndex] = imageResult.Error

	table.Append(row)
	table.Render()

	return builder.String()
}

func (results ScrubResults) PrintScrubResults(resultWriter io.Writer) {
	var builder strings.Builder

	printScrubTableHeader(&builder)
	fmt.Fprint(resultWriter, builder.String())

	for _, res := range results.ScrubResults {
		imageResult := printImageResult(res)
		fmt.Fprint(resultWriter, imageResult)
	}
}
