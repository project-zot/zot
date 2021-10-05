package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"

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
	ImageName string `json:"image_name"`
	Tag       string `json:"tag"`
	Status    string `json:"status"`
	Error     string `json:"error"`
}

type ScrubResults struct {
	ScrubResults []ScrubImageResult `json:"scrub_results"`
}

func (sc StoreController) CheckAllBlobsIntegrity() (ScrubResults, error) {
	results := ScrubResults{}

	imageStoreList := make(map[string]ImageStore)
	if sc.SubStore != nil {
		imageStoreList = sc.SubStore
	}

	imageStoreList[""] = sc.DefaultStore

	for _, is := range imageStoreList {
		images, err := is.GetRepositories()

		if err != nil {
			return results, err
		}

		for _, repo := range images {
			imageResults, err := checkImage(repo, is)

			if err != nil {
				return results, err
			}

			results.ScrubResults = append(results.ScrubResults, imageResults...)
		}
	}

	return results, nil
}

func checkImage(imageName string, is ImageStore) ([]ScrubImageResult, error) {
	results := []ScrubImageResult{}

	dir := path.Join(is.RootDir(), imageName)
	if !is.DirExists(dir) {
		return results, errors.ErrRepoNotFound
	}

	ctxUmoci := context.Background()

	oci, err := umoci.OpenLayout(dir)
	if err != nil {
		return results, err
	}

	defer oci.Close()

	is.RLock()
	defer is.RUnlock()

	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))

	if err != nil {
		return results, err
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		return results, errors.ErrRepoNotFound
	}

	for _, m := range index.Manifests {
		tag, ok := m.Annotations[ispec.AnnotationRefName]
		if ok {
			imageResult := checkIntegrity(ctxUmoci, imageName, tag, oci, m, dir)
			results = append(results, imageResult)
		}
	}

	return results, nil
}

func checkIntegrity(ctx context.Context, imageName, tagName string, oci casext.Engine, manifest ispec.Descriptor,
	dir string) ScrubImageResult {
	// check manifest and config
	stat, err := umoci.Stat(ctx, oci, manifest)

	imageRes := ScrubImageResult{}

	if err != nil {
		imageRes = getResult(imageName, tagName, err)
	} else {
		// check layers
		for _, s := range stat.History {
			layer := s.Layer
			if layer == nil {
				continue
			}

			// check layer
			layerPath := path.Join(dir, "blobs", layer.Digest.Algorithm().String(), layer.Digest.Hex())

			_, err = os.Stat(layerPath)
			if err != nil {
				imageRes = getResult(imageName, tagName, errors.ErrBlobNotFound)
				break
			}

			f, err := os.Open(layerPath)
			if err != nil {
				imageRes = getResult(imageName, tagName, errors.ErrBlobNotFound)
				break
			}

			computedDigest, err := godigest.FromReader(f)
			f.Close()

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

func printScrubTableHeader(writer io.Writer) {
	table := getScrubTableWriter(writer)

	row := make([]string, 4)

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

	row := make([]string, 4)

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
