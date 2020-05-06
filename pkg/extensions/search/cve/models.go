// Referred from https://github.com/kotakanbe/go-cve-dictionary/blob/master/models/models.go
package cveinfo

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/anuvu/zot/pkg/log"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"go.etcd.io/bbolt"
)

//NvdJSON ...
type NvdJSON struct {
	DataType    string    `json:"CVE_data_type"`
	DataFormat  string    `json:"CVE_data_format"`
	DataVersion string    `json:"CVE_data_version"`
	NumberCVES  string    `json:"CVE_data_numberOfCVEs"`
	TimeStamp   string    `json:"CVE_data_timestamp"`
	CVEItems    []CVEItem `json:"CVE_Items"`
}

//CVEItem ...
type CVEItem struct {
	Cve              CVE              `json:"cve"`
	Configuration    CVEConfiguration `json:"configurations"`
	Impact           Impact           `json:"impact"`
	PublishedDate    string           `json:"publishedDate"`
	LastModifiedDate string           `json:"lastModifiedDate"`
}

//CVE ...
type CVE struct {
	DataType    string         `json:"data_type"`
	DataFormat  string         `json:"data_format"`
	DataVersion string         `json:"data_version"`
	CVEDataMeta CVEMeta        `json:"CVE_data_meta"`
	ProblemType ProblemType    `json:"problemtype"`
	References  References     `json:"references"`
	Description CVEDescription `json:"description"`
}

//ProblemType ...
type ProblemType struct {
	ProblemTypeData []ProblemTypeData `json:"problemtype_data"`
}

// ProblemTypeData ...
type ProblemTypeData struct {
	ProblemDescription []DescriptionData `json:"description"`
}

// DescriptionData ...
type DescriptionData struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// References ...
type References struct {
	ReferenceData []ReferenceData `json:"reference_data"`
}

// ReferenceData ...
type ReferenceData struct {
	URL       string   `json:"url"`
	Name      string   `json:"name"`
	RefSource string   `json:"refsource"`
	Tags      []string `json:"tags"`
}

// CVEMeta ...
type CVEMeta struct {
	ID       string `json:"ID"`
	Assigner string `json:"ASSIGNER"`
}

// CVEConfiguration ...
type CVEConfiguration struct {
	DataVersion string      `json:"CVE_data_version"`
	Nodes       []ConfNodes `json:"nodes"`
}

// Impact ...
type Impact struct {
	BasicMetricV2 BasicMetricV2 `json:"baseMetricV2"`
}

// BasicMetricV2 ...
type BasicMetricV2 struct {
	CvssV2                  Cvss2   `json:"cvssV2"`
	Severity                string  `json:"severity"`
	ExploitabilityScore     float32 `json:"exploitabilityScore"`
	ImpactScore             float32 `json:"impactScore"`
	AcInsufInfo             bool    `json:"acInsufInfo"`
	ObtainAllPrivelege      bool    `json:"obtainAllPrivilege"`
	ObtainUserPrivelege     bool    `json:"obtainUserPrivilege"`
	ObtainOtherPrivelege    bool    `json:"obtainOtherPrivilege"`
	UserInteractionRequired bool    `json:"userInteractionRequired"`
}

// BasicMetricV3 ...
type BasicMetricV3 struct {
	CvssV3              Cvss2   `json:"cvssV2"`
	ExploitabilityScore float32 `json:"exploitabilityScore"`
	ImpactScore         float32 `json:"impactScore"`
}

// Cvss2 ...
type Cvss2 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AccessVector          string  `json:"accessVector"`
	AccessComplexity      string  `json:"accessComplexity"`
	Authentication        string  `json:"authentication"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float32 `json:"baseScore"`
}

// Cvss3 ...
type Cvss3 struct {
	Version               string `json:"version"`
	VectorString          string `json:"vectorString"`
	AttackVector          string `json:"attackVector"`
	AttackComplexity      string `json:"attackComplexity"`
	PrivelegeRequired     string `json:"privilegesRequired"`
	UserInteraction       string `json:"userInteraction"`
	Scope                 string `json:"scope"`
	ConfidentialityImpact string `json:"confidentialityImpact"`
	IntegrityImpact       string `json:"integrityImpact"`
	AvailabilityImpact    string `json:"availabilityImpact"`
	BaseScore             string `json:"baseScore"`
}

// ConfNodes ...
type ConfNodes struct {
	Operator string     `json:"operator"`
	Children []Children `json:"children"`
	CPEMatch []CPEMatch `json:"cpe_match"`
}

// Children ...
type Children struct {
	Operator string     `json:"operator"`
	CPEMatch []CPEMatch `json:"cpe_match"`
}

// CPEMatch ...
type CPEMatch struct {
	Vulnerable bool   `json:"vulnerable"`
	Cpe23Uri   string `json:"cpe23Uri"`
}

// CVEDescription ...
type CVEDescription struct {
	DescriptionData []CVEDescriptionData `json:"description_data"`
}

// CVEDescriptionData ...
type CVEDescriptionData struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// ImageLayers ...
type ImageLayers struct {
	SchemaVersion int32            `json:"schemaVersion"`
	Config        ImageLayerConfig `json:"config"`
}

// ImageLayerConfig ...
type ImageLayerConfig struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int32  `json:"size"`
}

// Schema ...
type Schema struct {
	CveID      string
	VulDesc    string
	VulDetails []VulDetail
}

// VulDetail ...
type VulDetail struct {
	PkgVendor  string
	PkgName    string
	PkgVersion string
}

// PkgName ...
type PkgName struct {
	Name   string
	CVEIds []CVEId
}

// PkgNameVer ...
type PkgNameVer struct {
	Name   string
	CVEIds []CVEId
}

// PkgVendor ...
type PkgVendor struct {
	Name   string
	CVEIds []CVEId
}

// CVEId ...
type CVEId struct {
	Name string
}

// CveInfo ...
type CveInfo struct {
	Log log.Logger
}

// InitDB ...
func (cve CveInfo) InitDB(dbPath string) *bbolt.DB {
	var db *bbolt.DB

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		db = cve.Connect(dbPath)
		nvdjsondb := cve.CreateBucket(NvdDB, db)
		pkgvendordb := cve.CreateBucket(VendorDB, db)
		pkgnamedb := cve.CreateBucket(NameDB, db)
		pkgnameverdb := cve.CreateBucket(NameverDB, db)
		nvdmeatabd := cve.CreateBucket(NvdmetaDB, db)

		// If not able to create a bucket, this should return nil
		if !nvdjsondb || !nvdmeatabd || !pkgvendordb || !pkgnamedb || !pkgnameverdb {
			return nil
		}
	} else {
		db = cve.Connect(dbPath)
	}

	return db
}

// StartUpdate ...
func (cve CveInfo) StartUpdate(dbDir string, startYear int, endYear int) error {
	if _, err := os.Stat(dbDir); os.IsNotExist(err) {
		if err := os.MkdirAll(dbDir, 0700); err != nil {
			cve.Log.Error().Err(err).Str("rootDir", dbDir).Msg("unable to create root dir")
			return nil
		}
	}

	db := cve.InitDB(path.Join(dbDir, "search.db"))

	if db == nil {
		return errors.New("unable to open db")
	}

	err := cve.getNvdData(dbDir, startYear, endYear, db)

	defer Close(db)

	return err
}

// GetImageAnnotations ...
func (cve CveInfo) GetImageAnnotations(repo string) (map[string][]string, error) {
	dir := path.Join("/tmp/zot", repo)
	if !dirExists(dir) {
		cve.Log.Error().Msg("Image Directory not exists")

		return nil, nil
	}

	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))

	if err != nil {
		if os.IsNotExist(err) {
			cve.Log.Error().Err(err).Msg("Index.json does not exist")

			return nil, nil
		}

		cve.Log.Error().Err(err).Msg("Unable to open index.json")

		return nil, nil
	}

	var index ispec.Index

	var blobIndex ImageLayers

	var layerIndex ispec.Image

	if err := json.Unmarshal(buf, &index); err != nil {
		cve.Log.Error().Err(err).Msg("Unable to marshal index.json file")

		return nil, nil
	}

	tagpkgMap := make(map[string][]string)

	for _, m := range index.Manifests {
		pkgList := make([]string, 0)
		v, ok := m.Annotations[ispec.AnnotationRefName]

		blobFile := strings.Split(m.Digest.String(), ":")[1]

		// If there is no tag associated with Image, consider its sha256 as a tag
		if !ok {
			v = blobFile
		}

		blobBuf, err := ioutil.ReadFile(path.Join(path.Join(dir, "blobs", "sha256"), blobFile))
		if err != nil {
			cve.Log.Error().Err(err).Msg("Unable to open Image Metadata file")
		}

		if err := json.Unmarshal(blobBuf, &blobIndex); err != nil {
			cve.Log.Error().Err(err).Msg("Unable to marshal blob index")

			return nil, nil
		}

		layerFile := strings.Split(blobIndex.Config.Digest, ":")[1]

		blobBuf, err = ioutil.ReadFile(path.Join(path.Join(dir, "blobs", "sha256"), layerFile))
		if err != nil {
			cve.Log.Error().Err(err).Msg("Unable to open Image Layers file")
		}

		if err := json.Unmarshal(blobBuf, &layerIndex); err != nil {
			cve.Log.Error().Err(err).Msg("Unable to marshal blob index")

			return nil, nil
		}

		for _, v := range layerIndex.Config.Labels {
			pkgList = append(pkgList, v)
		}

		tagpkgMap[v] = pkgList
	}

	return tagpkgMap, nil
}

// GetNvdData ...
//This function downloads the .meta files, reads the hashcode of json files,
//compares it in database and if not found, downloads the JSON file in zip format.
func (cve CveInfo) getNvdData(filepath string, startYear int, endYear int, db *bbolt.DB) error {
	var header = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"

	for i := startYear; i < endYear; i++ {
		// Meta File Name
		metaFileName := strconv.FormatUint(uint64(i), 10) + ".meta"
		// Json File Name
		jsonFileName := "nvdcve-1.1-" + strconv.FormatUint(uint64(i), 10) + ".json"
		// Zip File Name
		zipFileName := strconv.FormatUint(uint64(i), 10) + ".json.zip"
		// URL to download Meta File
		metaURL := header + metaFileName
		// URL to download Zip file
		zipURL := header + zipFileName
		// Downloading Meta file
		err := downloadFile(path.Join(filepath, metaFileName), metaURL)
		if err != nil {
			cve.Log.Error().Err(err).Msg("Not able to Download the Meta file")

			return err
		}
		// Opening the Meta File
		file, err := os.Open(path.Join(filepath, metaFileName))
		if err != nil {
			cve.Log.Error().Err(err).Msg("Not able to open meta file")

			return err
		}
		// Scanning the .meta file to find SHA256 code
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "sha256") {
				hashcode := strings.Split(line, ":")[1]
				// Checking if file having same name and hashcode is already downloaded...
				if !cve.isPresent(metaFileName, hashcode, db) {
					err := downloadFile(path.Join(filepath, zipFileName), zipURL)
					if err != nil {
						return err
					}

					err = unzipFiles(filepath, zipFileName)
					if err != nil {
						return err
					}

					nvdjson, jsonErr := readJSON(path.Join(filepath, jsonFileName))
					if jsonErr != nil {
						return jsonErr
					}

					nvdschema, mapList := extractSchema(nvdjson)
					// Updating the NVD Data
					err = cve.updateNVD(nvdschema, mapList, db)
					if err != nil {
						cve.Log.Error().Err(err).Msg("Unable to update Nvd Data")
					}
					// Updating the NVD Meta Db
					err = cve.updateNVDMeta(metaFileName, hashcode, db)
					if err != nil {
						cve.Log.Error().Err(err).Msg("Unable to update Nvd Meta")
					}
				}
			}
		}
	}

	err := removeFiles(filepath)
	if err != nil {
		cve.Log.Error().Err(err).Msg("Unable to Remove downloaded files")
	}

	return err
}

/* Download and saves the file with given filepath */
func downloadFile(filepath string, url string) error {
	// nolint (gosec)
	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)

	return err
}

/* Unzipping the files and storing all the unzipped files */
func unzipFiles(filepath string, filename string) error {
	// Unzipping zip file
	reader, err := zip.OpenReader(path.Join(filepath, filename))
	if err != nil {
		return err
	}

	files := reader.File
	// Creating a unzipped file
	outFile, err := os.Create(path.Join(filepath, files[0].Name))
	if err != nil {
		return err
	}

	// Reading from unzipped file
	readJSON, err := files[0].Open()
	if err != nil {
		return err
	}

	_, err = io.Copy(outFile, readJSON)

	return err
}

/*ReadJSON ... Reading the JSON files */
func readJSON(filepath string) (NvdJSON, error) {
	var nvdjson NvdJSON

	byteValue, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nvdjson, err
	}

	err = json.Unmarshal(byteValue, &nvdjson)
	if err != nil {
		return nvdjson, err
	}

	return nvdjson, nil
}

/*ExtractSchema ... Extracting the Schema */
func extractSchema(nvdjson NvdJSON) ([]Schema, []map[string][]CVEId) {
	var (
		// This variable stores list of CVEIds and its detailed description
		schemas []Schema
		// Map of pkgvendor and list of cveids per json file
		pkgvendors  = make(map[string][]CVEId)
		pkgnames    = make(map[string][]CVEId)
		pkgnamevers = make(map[string][]CVEId)
	)
	// List of pkgvendor, pkgname and pkgnameversion
	var mapList []map[string][]CVEId

	cveitems := nvdjson.CVEItems
	// Iterating through the cveitems
	for _, cveitem := range cveitems {
		// Every cveitem is unique hence unique schema
		schema := Schema{}
		// Unique cveid
		cveid := CVEId{}
		// Every Cveid or Cveitem contains list of vulnerabilities
		vuldescs := []VulDetail{}
		// Every Cveid or Cveitem has vulnerabilities. Storing only unique PkgVendor, Name and Versions
		vendorSet := map[string]struct{}{}
		nameSet := map[string]struct{}{}
		nameverSet := map[string]struct{}{}
		// Assigning the values
		cveid.Name = cveitem.Cve.CVEDataMeta.ID
		schema.CveID = cveitem.Cve.CVEDataMeta.ID
		schema.VulDesc = cveitem.Cve.Description.DescriptionData[0].Value
		// All Vulnerabilities details are on configuration nodes
		nodes := cveitem.Configuration.Nodes
		if len(nodes) == 0 {
			continue
		}
		// Iterating through nodes
		for _, node := range nodes {
			// Node contains either CPEMatch or Children
			if len(node.CPEMatch) == 0 {
				for _, child := range node.Children {
					for _, cpematch := range child.CPEMatch {
						vuldesc := VulDetail{}
						cpe23uri := cpematch.Cpe23Uri
						// Cpe23 Uri contains details about package and spearted by ":", hence splitting
						splits := strings.Split(cpe23uri, ":")

						// Updating the Vulnerability Details cpe:2.3:o:bsdi:bsd_os:3.1:*:*:*:*:*:*:*
						vuldesc.PkgVendor = splits[3]
						vuldesc.PkgName = splits[4]
						vuldesc.PkgVersion = splits[5]
						vuldescs = append(vuldescs, vuldesc)
						// Updating Package Vendor Map
						//list := []CVEId{}
						list, ok := pkgvendors[splits[3]]
						if ok {
							_, ok := vendorSet[splits[3]]
							if !ok {
								list = append(list, cveid)
								vendorSet[splits[3]] = struct{}{}
							}
						} else {
							list = append(list, cveid)
							vendorSet[splits[3]] = struct{}{}
						}

						pkgvendors[splits[3]] = list

						// Updating Package Name Map
						//list = []CVEId{}
						list, ok = pkgnames[splits[4]]
						if ok {
							_, ok = nameSet[splits[4]]
							if !ok {
								list = append(list, cveid)
								nameSet[splits[4]] = struct{}{}
							}
						} else {
							list = append(list, cveid)
							nameSet[splits[4]] = struct{}{}
						}

						pkgnames[splits[4]] = list

						// Updating Package Name Version Map
						//list = []CVEId{}
						list, ok = pkgnamevers[splits[4]+splits[5]]
						if ok {
							_, ok = nameverSet[splits[4]+splits[5]]
							if !ok {
								list = append(list, cveid)
								nameverSet[splits[4]+splits[5]] = struct{}{}
							}
						} else {
							list = append(list, cveid)
							nameverSet[splits[4]+splits[5]] = struct{}{}
						}

						pkgnamevers[splits[4]+splits[5]] = list
					}
				}
			} else {
				for _, cpematch := range node.CPEMatch {
					cpe23uri := cpematch.Cpe23Uri
					splits := strings.Split(cpe23uri, ":")

					// Adding Vulnerabilities Details...
					vuldesc := VulDetail{}
					vuldesc.PkgVendor = splits[3]
					vuldesc.PkgName = splits[4]
					vuldesc.PkgVersion = splits[5]
					vuldescs = append(vuldescs, vuldesc)
					//list := []CVEId{}
					list, ok := pkgvendors[splits[3]]
					if ok {
						_, ok := vendorSet[splits[3]]
						if !ok {
							list = append(list, cveid)
							vendorSet[splits[3]] = struct{}{}
						}
					} else {
						list = append(list, cveid)
						vendorSet[splits[3]] = struct{}{}
					}

					pkgvendors[splits[3]] = list

					// Updating Package Name Map
					//list = []CVEId{}
					list, ok = pkgnames[splits[4]]
					if ok {
						_, ok = nameSet[splits[4]]
						if !ok {
							list = append(list, cveid)
							nameSet[splits[4]] = struct{}{}
						}
					} else {
						list = append(list, cveid)
						nameSet[splits[4]] = struct{}{}
					}

					pkgnames[splits[4]] = list

					// Updating Package Name Version Map
					//list = []CVEId{}
					list, ok = pkgnamevers[splits[4]+splits[5]]
					if ok {
						_, ok = nameverSet[splits[4]+splits[5]]
						if !ok {
							list = append(list, cveid)
							nameverSet[splits[4]+splits[5]] = struct{}{}
						}
					} else {
						list = append(list, cveid)
						nameverSet[splits[4]+splits[5]] = struct{}{}
					}

					pkgnamevers[splits[4]+splits[5]] = list
				}
			}
		}

		if len(vuldescs) != 0 {
			schema.VulDetails = vuldescs
			schemas = append(schemas, schema)
		}
	}
	// nolint (wsl)
	mapList = append(mapList, pkgvendors, pkgnames, pkgnamevers)

	return schemas, mapList
}

func removeFiles(filePath string) error {
	files, err := filepath.Glob(path.Join(filePath, "*.json"))
	if err != nil {
		return err
	}

	for _, f := range files {
		if err := os.Remove(f); err != nil {
			return err
		}
	}

	files, err = filepath.Glob(path.Join(filePath, "*.meta"))
	if err != nil {
		return err
	}

	for _, f := range files {
		if err := os.Remove(f); err != nil {
			return err
		}
	}

	files, err = filepath.Glob(path.Join(filePath, "*.json.zip"))
	if err != nil {
		panic(err)
	}

	for _, f := range files {
		if err := os.Remove(f); err != nil {
			panic(err)
		}
	}

	return nil
}

func dirExists(d string) bool {
	fi, err := os.Stat(d)
	if err != nil && os.IsNotExist(err) {
		return false
	}

	if !fi.IsDir() {
		return false
	}

	return true
}
