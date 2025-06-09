package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/common"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
)

const (
	colImageNameIndex = iota
	colTagIndex
	colStatusIndex
	colAffectedBlobIndex
	colErrorIndex

	imageNameWidth    = 32
	tagWidth          = 24
	statusWidth       = 8
	affectedBlobWidth = 64
	errorWidth        = 8
)

type ScrubImageResult struct {
	ImageName    string `json:"imageName"`
	Tag          string `json:"tag"`
	Status       string `json:"status"`
	AffectedBlob string `json:"affectedBlob"`
	Error        string `json:"error"`
}

type ScrubResults struct {
	ScrubResults []ScrubImageResult `json:"scrubResults"`
}

func (sc StoreController) CheckAllBlobsIntegrity(ctx context.Context) (ScrubResults, error) {
	results := ScrubResults{}

	imageStoreList := make(map[string]storageTypes.ImageStore)
	if sc.SubStore != nil {
		imageStoreList = sc.SubStore
	}

	imageStoreList[""] = sc.DefaultStore

	for _, imgStore := range imageStoreList {
		imgStoreResults, err := CheckImageStoreBlobsIntegrity(ctx, imgStore)
		if err != nil {
			return results, err
		}

		results.ScrubResults = append(results.ScrubResults, imgStoreResults...)
	}

	return results, nil
}

func CheckImageStoreBlobsIntegrity(ctx context.Context, imgStore storageTypes.ImageStore) ([]ScrubImageResult, error) {
	results := []ScrubImageResult{}

	repos, err := imgStore.GetRepositories()
	if err != nil {
		return results, err
	}

	for _, repo := range repos {
		imageResults, err := CheckRepo(ctx, repo, imgStore)
		if err != nil {
			return results, err
		}

		results = append(results, imageResults...)
	}

	return results, nil
}

// CheckRepo is the main entry point for the scrub task
// We aim for eventual consistency (locks, etc) since this task contends with data path.
func CheckRepo(ctx context.Context, imageName string, imgStore storageTypes.ImageStore) ([]ScrubImageResult, error) {
	results := []ScrubImageResult{}

	// getIndex holds the lock
	indexContent, err := getIndex(imageName, imgStore)
	if err != nil {
		return results, err
	}

	var index ispec.Index
	if err := json.Unmarshal(indexContent, &index); err != nil {
		return results, zerr.ErrRepoNotFound
	}

	scrubbedManifests := make(map[godigest.Digest]ScrubImageResult)

	for _, manifest := range index.Manifests {
		if common.IsContextDone(ctx) {
			return results, ctx.Err()
		}

		tag := manifest.Annotations[ispec.AnnotationRefName]

		// checkImage holds the lock
		layers, err := checkImage(manifest, imgStore, imageName, tag, scrubbedManifests)
		if err == nil && len(layers) > 0 {
			// CheckLayers doesn't use locks
			imgRes := CheckLayers(imageName, tag, layers, imgStore)
			scrubbedManifests[manifest.Digest] = imgRes
		}

		// ignore the manifest if it isn't found
		if !errors.Is(err, zerr.ErrManifestNotFound) {
			results = append(results, scrubbedManifests[manifest.Digest])
		}
	}

	return results, nil
}

func checkImage(
	manifest ispec.Descriptor, imgStore storageTypes.ImageStore, imageName, tag string,
	scrubbedManifests map[godigest.Digest]ScrubImageResult,
) ([]ispec.Descriptor, error) {
	var lockLatency time.Time

	imgStore.RLock(&lockLatency)
	defer imgStore.RUnlock(&lockLatency)

	manifestContent, err := imgStore.GetBlobContent(imageName, manifest.Digest)
	if err != nil {
		// ignore if the manifest is not found(probably it was deleted after we got the list of manifests)
		return []ispec.Descriptor{}, zerr.ErrManifestNotFound
	}

	return scrubManifest(manifest, imgStore, imageName, tag, manifestContent, scrubbedManifests)
}

func getIndex(imageName string, imgStore storageTypes.ImageStore) ([]byte, error) {
	var lockLatency time.Time

	imgStore.RLock(&lockLatency)
	defer imgStore.RUnlock(&lockLatency)

	// check image structure / layout
	ok, err := imgStore.ValidateRepo(imageName)
	if err != nil {
		return []byte{}, err
	}

	if !ok {
		return []byte{}, zerr.ErrRepoBadLayout
	}

	// check "index.json" content
	indexContent, err := imgStore.GetIndexContent(imageName)
	if err != nil {
		return []byte{}, err
	}

	return indexContent, nil
}

func scrubManifest(
	manifest ispec.Descriptor, imgStore storageTypes.ImageStore, imageName, tag string,
	manifestContent []byte, scrubbedManifests map[godigest.Digest]ScrubImageResult,
) ([]ispec.Descriptor, error) {
	layers := []ispec.Descriptor{}

	res, ok := scrubbedManifests[manifest.Digest]
	if ok {
		scrubbedManifests[manifest.Digest] = newScrubImageResult(imageName, tag, res.Status,
			res.AffectedBlob, res.Error)

		return layers, nil
	}

	switch manifest.MediaType {
	case ispec.MediaTypeImageIndex:
		var idx ispec.Index
		if err := json.Unmarshal(manifestContent, &idx); err != nil {
			imgRes := getResult(imageName, tag, manifest.Digest, zerr.ErrBadBlobDigest)
			scrubbedManifests[manifest.Digest] = imgRes

			return layers, err
		}

		// check all manifests
		for _, man := range idx.Manifests {
			buf, err := imgStore.GetBlobContent(imageName, man.Digest)
			if err != nil {
				imgRes := getResult(imageName, tag, man.Digest, zerr.ErrBadBlobDigest)
				scrubbedManifests[man.Digest] = imgRes
				scrubbedManifests[manifest.Digest] = imgRes

				return layers, err
			}

			layersToScrub, err := scrubManifest(man, imgStore, imageName, tag, buf, scrubbedManifests)
			if err == nil {
				layers = append(layers, layersToScrub...)
			}

			// if the manifest is affected then this index is also affected
			if scrubbedManifests[man.Digest].Error != "" {
				mRes := scrubbedManifests[man.Digest]

				scrubbedManifests[manifest.Digest] = newScrubImageResult(imageName, tag, mRes.Status,
					mRes.AffectedBlob, mRes.Error)

				return layers, err
			}
		}

		// at this point, before starting to check the subject we can consider the index is ok
		scrubbedManifests[manifest.Digest] = getResult(imageName, tag, "", nil)

		// check subject if exists
		if idx.Subject != nil {
			buf, err := imgStore.GetBlobContent(imageName, idx.Subject.Digest)
			if err != nil {
				imgRes := getResult(imageName, tag, idx.Subject.Digest, zerr.ErrBadBlobDigest)
				scrubbedManifests[idx.Subject.Digest] = imgRes
				scrubbedManifests[manifest.Digest] = imgRes

				return layers, err
			}

			layersToScrub, err := scrubManifest(*idx.Subject, imgStore, imageName, tag, buf, scrubbedManifests)
			if err == nil {
				layers = append(layers, layersToScrub...)
			}

			subjectRes := scrubbedManifests[idx.Subject.Digest]

			scrubbedManifests[manifest.Digest] = newScrubImageResult(imageName, tag, subjectRes.Status,
				subjectRes.AffectedBlob, subjectRes.Error)

			return layers, err
		}

		return layers, nil
	case ispec.MediaTypeImageManifest:
		affectedBlob, man, err := CheckManifestAndConfig(imageName, manifest, manifestContent, imgStore)
		if err == nil {
			layers = append(layers, man.Layers...)
		}

		scrubbedManifests[manifest.Digest] = getResult(imageName, tag, affectedBlob, err)

		// if integrity ok then check subject if exists
		if err == nil && man.Subject != nil {
			buf, err := imgStore.GetBlobContent(imageName, man.Subject.Digest)
			if err != nil {
				imgRes := getResult(imageName, tag, man.Subject.Digest, zerr.ErrBadBlobDigest)
				scrubbedManifests[man.Subject.Digest] = imgRes
				scrubbedManifests[manifest.Digest] = imgRes

				return layers, err
			}

			layersToScrub, err := scrubManifest(*man.Subject, imgStore, imageName, tag, buf, scrubbedManifests)
			if err == nil {
				layers = append(layers, layersToScrub...)
			}

			subjectRes := scrubbedManifests[man.Subject.Digest]

			scrubbedManifests[manifest.Digest] = newScrubImageResult(imageName, tag, subjectRes.Status,
				subjectRes.AffectedBlob, subjectRes.Error)

			return layers, err
		}

		return layers, err
	default:
		scrubbedManifests[manifest.Digest] = getResult(imageName, tag, manifest.Digest, zerr.ErrBadManifest)

		return layers, zerr.ErrBadManifest
	}
}

func CheckManifestAndConfig(
	imageName string, manifestDesc ispec.Descriptor, manifestContent []byte, imgStore storageTypes.ImageStore,
) (godigest.Digest, ispec.Manifest, error) {
	if manifestDesc.MediaType != ispec.MediaTypeImageManifest {
		return manifestDesc.Digest, ispec.Manifest{}, zerr.ErrBadManifest
	}

	var manifest ispec.Manifest

	err := json.Unmarshal(manifestContent, &manifest)
	if err != nil {
		return manifestDesc.Digest, ispec.Manifest{}, zerr.ErrBadManifest
	}

	configContent, err := imgStore.GetBlobContent(imageName, manifest.Config.Digest)
	if err != nil {
		return manifest.Config.Digest, ispec.Manifest{}, err
	}

	var config ispec.Image

	err = json.Unmarshal(configContent, &config)
	if err != nil {
		return manifest.Config.Digest, ispec.Manifest{}, zerr.ErrBadConfig
	}

	return "", manifest, nil
}

func CheckLayers(
	imageName, tagName string, layers []ispec.Descriptor, imgStore storageTypes.ImageStore,
) ScrubImageResult {
	imageRes := ScrubImageResult{}

	for _, layer := range layers {
		if err := imgStore.VerifyBlobDigestValue(imageName, layer.Digest); err != nil {
			imageRes = getResult(imageName, tagName, layer.Digest, err)

			break
		}

		imageRes = getResult(imageName, tagName, "", nil)
	}

	return imageRes
}

func getResult(imageName, tag string, affectedBlobDigest godigest.Digest, err error) ScrubImageResult {
	if err != nil {
		return newScrubImageResult(imageName, tag, "affected", affectedBlobDigest.Encoded(), err.Error())
	}

	return newScrubImageResult(imageName, tag, "ok", "", "")
}

func newScrubImageResult(imageName, tag, status, affectedBlob, err string) ScrubImageResult {
	return ScrubImageResult{
		ImageName:    imageName,
		Tag:          tag,
		Status:       status,
		AffectedBlob: affectedBlob,
		Error:        err,
	}
}

func getScrubTableWriter(writer io.Writer) *tablewriter.Table {
	symbols := tw.NewSymbolCustom("Spaces").
		WithRow("").
		WithColumn(" ").
		WithTopLeft("").
		WithTopMid("").
		WithTopRight("").
		WithMidLeft("").
		WithCenter("").
		WithMidRight("").
		WithBottomLeft("").
		WithBottomMid("").
		WithBottomRight("")

	table := tablewriter.NewWriter(writer)

	// Configure table using the new builder pattern
	table.Options(
		tablewriter.WithRendition(tw.Rendition{
			Borders: tw.Border{
				Left:   tw.Off,
				Right:  tw.Off,
				Top:    tw.Off,
				Bottom: tw.Off,
			},
			Symbols: symbols,
			Settings: tw.Settings{
				Separators: tw.Separators{
					ShowHeader:     tw.Off,
					ShowFooter:     tw.Off,
					BetweenRows:    tw.Off,
					BetweenColumns: tw.On,
				},
			},
		}),
		tablewriter.WithPadding(tw.Padding{
			Left:  "",
			Right: "",
		}),
		tablewriter.WithHeaderAlignment(tw.AlignLeft),
		tablewriter.WithRowAlignment(tw.AlignLeft),
	)

	return table
}

const tableCols = 5

func printScrubTableHeader(table *tablewriter.Table) {
	row := make([]string, tableCols)

	row[colImageNameIndex] = "REPOSITORY"
	row[colTagIndex] = "TAG"
	row[colStatusIndex] = "STATUS"
	row[colAffectedBlobIndex] = "AFFECTED BLOB"
	row[colErrorIndex] = "ERROR"

	table.Append(row) //nolint:errcheck
}

func (results ScrubResults) PrintScrubResults(resultWriter io.Writer) {
	var builder strings.Builder

	table := getScrubTableWriter(&builder)
	printScrubTableHeader(table)

	imageNameLen := len("REPOSITORY")
	tagLen := len("TAG")
	errorLen := len("ERROR")

	for _, imageResult := range results.ScrubResults {
		imageNameLen = max(imageNameLen, len(imageResult.ImageName))
		tagLen = max(tagLen, len(imageResult.Tag))
		errorLen = max(errorLen, len(imageResult.Error))

		row := make([]string, tableCols)
		row[colImageNameIndex] = imageResult.ImageName
		row[colTagIndex] = imageResult.Tag
		row[colStatusIndex] = imageResult.Status
		row[colAffectedBlobIndex] = imageResult.AffectedBlob
		row[colErrorIndex] = imageResult.Error

		table.Append(row) //nolint:errcheck
	}

	imageNameLen = min(imageNameLen, imageNameWidth)
	tagLen = min(tagLen, tagWidth)

	table.Options(
		tablewriter.WithColumnWidths(tw.NewMapper[int, int]().
			Set(colImageNameIndex, imageNameLen).
			Set(colTagIndex, tagLen).
			Set(colStatusIndex, statusWidth).
			Set(colAffectedBlobIndex, affectedBlobWidth).
			Set(colErrorIndex, errorLen)),
	)

	table.Render() //nolint:errcheck
	fmt.Fprint(resultWriter, builder.String())
}
