//go:build search
// +build search

// nolint:lll,gosimple
package cveinfo_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	regTypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/extensions/search/common"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/extensions/search/cve/trivy"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	storConstants "zotregistry.io/zot/pkg/storage/constants"
	. "zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
)

// nolint:gochecknoglobals
var (
	cve            cveinfo.CveInfo
	dbDir          string
	updateDuration time.Duration
)

const (
	username   = "test"
	passphrase = "test"
)

type CveResult struct {
	ImgList ImgList `json:"data"`
}

//nolint:tagliatelle // graphQL schema
type ImgListWithCVEFixed struct {
	Images []ImageInfo `json:"ImageListWithCVEFixed"`
}

type ImageInfo struct {
	RepoName    string
	LastUpdated time.Time
}

//nolint:tagliatelle // graphQL schema
type ImgList struct {
	CVEResultForImage CVEResultForImage `json:"CVEListForImage"`
}

//nolint:tagliatelle // graphQL schema
type CVEResultForImage struct {
	Tag     string         `json:"Tag"`
	CVEList []cvemodel.CVE `json:"CVEList"`
}

func testSetup() error {
	dir, err := os.MkdirTemp("", "util_test")
	if err != nil {
		return err
	}

	log := log.NewLogger("debug", "")
	metrics := monitoring.NewMetricsServer(false, log)

	conf := config.New()
	conf.Extensions = &extconf.ExtensionConfig{}
	conf.Extensions.Lint = &extconf.LintConfig{}

	storeController := storage.StoreController{DefaultStore: local.NewImageStore(dir, false,
		storConstants.DefaultGCDelay, false, false, log, metrics, nil)}

	layoutUtils := common.NewBaseOciLayoutUtils(storeController, log)
	scanner := trivy.NewScanner(storeController, layoutUtils, log)

	cve = &cveinfo.BaseCveInfo{Log: log, Scanner: scanner, LayoutUtils: layoutUtils}

	dbDir = dir

	err = generateTestData()
	if err != nil {
		return err
	}

	err = CopyFiles("../../../../test/data", dbDir)
	if err != nil {
		return err
	}

	return nil
}

func generateTestData() error { // nolint: gocyclo
	// Image dir with no files
	err := os.Mkdir(path.Join(dbDir, "zot-noindex-test"), 0o755)
	if err != nil {
		return err
	}

	err = os.Mkdir(path.Join(dbDir, "zot-nonreadable-test"), 0o755)
	if err != nil {
		return err
	}

	index := ispec.Index{}
	index.SchemaVersion = 2

	buf, err := json.Marshal(index)
	if err != nil {
		return err
	}

	if err = os.WriteFile(path.Join(dbDir, "zot-nonreadable-test", "index.json"), buf, 0o111); err != nil {
		return err
	}

	// Image dir with invalid index.json
	err = os.Mkdir(path.Join(dbDir, "zot-squashfs-invalid-index"), 0o755)
	if err != nil {
		return err
	}

	content := `{"schemaVersion": 2,"manifests"[{"mediaType": "application/vnd.oci.image.manifest.v1+json","digest": "sha256:2a9b097b4e4c613dd8185eba55163201a221909f3d430f8df87cd3639afc5929","size": 1240,"annotations": {"org.opencontainers.image.ref.name": "commit-aaa7c6e7-squashfs"},"platform": {"architecture": "amd64","os": "linux"}}]}`

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-invalid-index", "index.json"), content)
	if err != nil {
		return err
	}

	// Image dir with no blobs
	err = os.Mkdir(path.Join(dbDir, "zot-squashfs-noblobs"), 0o755)
	if err != nil {
		return err
	}

	content = `{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:2a9b097b4e4c613dd8185eba55163201a221909f3d430f8df87cd3639afc5929","size":1240,"annotations":{"org.opencontainers.image.ref.name":"commit-aaa7c6e7-squashfs"},"platform":{"architecture":"amd64","os":"linux"}}]}`

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-noblobs", "index.json"), content)
	if err != nil {
		return err
	}

	// Image dir with invalid blob
	err = os.MkdirAll(path.Join(dbDir, "zot-squashfs-invalid-blob", "blobs/sha256"), 0o755)
	if err != nil {
		return err
	}

	content = fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:2a9b097b4e4c613dd8185eba55163201a221909f3d430f8df87cd3639afc5929","size":1240,"annotations":{"org.opencontainers.image.ref.name":"commit-aaa7c6e7-squashfs"},"platform":{"architecture":"amd64","os":"linux"}}]}
	`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-invalid-blob", "index.json"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprintf(`{"schemaVersion":2,"config"{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:4b37d4133908ac9a3032ba996020f2ad41354a616b071ca7e726a1df18a0f354","size":1691},"layers":[{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:a01a66356aace53222e92fb6fd990b23eb44ab0e58dff6f853fa9f771ecf3ac5","size":54996992},{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:91c26d6934ef2b5c5c4d8458af9bfc4ca46cf90c22380193154964abc8298a7a","size":52330496},{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:f281a550ca49746cfc6b8f1ac52f8086b3d5845db2ca18fde980dab62ae3bf7d","size":23343104},{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:7ee02568717acdda336c9d56d4dc6ea7f3b1c553e43bb0c0ecc6fd3bbd059d1a","size":5910528},{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:8fb33b130588b239235dedd560cdf49d29bbf6f2db5419ac68e4592a85c1f416","size":123269120},{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:1b49f0b33d4a696bb94d84c9acab3623e2c195bfb446d446a583a2f9f27b04c3","size":113901568}],"annotations":{"com.cisco.stacker.git_version":"7-dev19-63-gaaa7c6e7","ws.tycho.stacker.git_version":"0.3.26"}}
	`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-invalid-blob", "blobs/sha256", "2a9b097b4e4c613dd8185eba55163201a221909f3d430f8df87cd3639afc5929"), content)
	if err != nil {
		return err
	}

	// Create a squashfs image

	err = os.MkdirAll(path.Join(dbDir, "zot-squashfs-test", "blobs/sha256"), 0o755)
	if err != nil {
		return err
	}

	il := ispec.ImageLayout{Version: ispec.ImageLayoutVersion}
	buf, err = json.Marshal(il)

	if err != nil {
		return err
	}

	if err = os.WriteFile(path.Join(dbDir, "zot-squashfs-test", "oci-layout"), buf, 0o644); err != nil { //nolint: gosec
		return err
	}

	err = os.Mkdir(path.Join(dbDir, "zot-squashfs-test", ".uploads"), 0o755)
	if err != nil {
		return err
	}

	content = fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb","size":886,"annotations":{"org.opencontainers.image.ref.name":"0.3.25"},"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:45df53588e59759a12bd3eca553cdc9063939baac9a28d7ebb6101e4ec230b76","size":873,"annotations":{"org.opencontainers.image.ref.name":"0.3.22-squashfs"},"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:71448405a4b89539fcfa581afb4dc7d257f98857686b8138b08a1c539f313099","size":886,"annotations":{"org.opencontainers.image.ref.name":"0.3.19"},"platform":{"architecture":"amd64","os":"linux"}}]}`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-test", "index.json"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:c5c2fd2b07ad4cb025cf20936d6bce6085584b8377780599be4da8a91739f0e8","size":1738},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:3414b5ef0ad2f0390daaf55b63c422eeedef6191d47036a69d8ee396fabdce72","size":58993484},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:a3b04fff744c13dfa4883e01fa35e01af8daa7f72d9e9b6b7fad1f28843846b6","size":55631733},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:754f517f58f302190aa94e025c25890c18e1e811127aed1ef25c189278ec4ab0","size":113612795},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:ec004cd43488b803d6e232599e83a3164394d44fcd9f44755fed7b5791087ede","size":108889651}],"annotations":{"ws.tycho.stacker.git_version":"0.3.19"}}`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-test", "blobs/sha256", "71448405a4b89539fcfa581afb4dc7d257f98857686b8138b08a1c539f313099"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprintf(`{"created": "2020-04-08T05:32:49.805795564Z","author": "","architecture": "amd64","os": "linux","config": {"Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]},"rootfs": {"type": "layers","diff_ids": []},"history": [{"created": "2020-04-08T05:08:43.590117872Z","created_by": "stacker umoci repack"}, {"created": "2020-04-08T05:08:53.213437118Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:12:15.999154739Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-04-08T05:12:31.0513552Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:20:38.068800557Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-04-08T05:21:01.956154957Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:32:24.582132274Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-04-08T05:32:49.805795564Z","created_by": "stacker build","author": "","empty_layer": true}]}`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-test", "blobs/sha256", "c5c2fd2b07ad4cb025cf20936d6bce6085584b8377780599be4da8a91739f0e8"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:5f00b5570a5561a6f9b7e66e4f26e2e30c4d09b43a8d3f993f3c1c99be6137a6","size":1740},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:f8b7e41ce10d9a0f614f068326c43431c2777e6fc346f729c2a643bfab24af83","size":59451113},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:9ca9274f196b56a708a7a672d3de88184c0158a30744d355dd0411f3a6850fa6","size":55685756},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:6c1ca50788f93937e9ce9341b564f86cbbcd28e367ed6a57cfc776aee4a9d050","size":113726186},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:d1a92139df86bdf00c818db75bf1ecc860857d142b426e9971a62f5f90e2aa57","size":108755643}],"annotations":{"ws.tycho.stacker.git_version":"0.3.25"}}`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-test", "blobs/sha256", "eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprintf(`{"created": "2020-04-08T05:32:49.805795564Z","author": "","architecture": "amd64","os": "linux","config": {"Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]},"rootfs": {"type": "layers","diff_ids": []},"history": [{"created": "2020-05-11T18:17:24.516727354Z","created_by": "stacker umoci repack"}, {"created": "2020-04-08T05:08:53.213437118Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:12:15.999154739Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-04-08T05:12:31.0513552Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:20:38.068800557Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-04-08T05:21:01.956154957Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:32:24.582132274Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-04-08T05:32:49.805795564Z","created_by": "stacker build","author": "","empty_layer": true}]}`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-test", "blobs/sha256", "5f00b5570a5561a6f9b7e66e4f26e2e30c4d09b43a8d3f993f3c1c99be6137a6"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:1fc1d045b241b04fea54333d76d4f57eb1961f9a314413f02a956b76e77a99f0","size":1218},"layers":[{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:c40d72b1556293c00a3e4b6c64c46ef4c7ae4d876dc18bad942b7d1903e8e5b7","size":54745420},{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:4115890e3e2563e545e03f264bfecb0097e24e02306ae3e7668dea52e00c6cc2","size":52213357},{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:91859e13e0cf704d5405199d73a2d1a0718391dbb183a77c4cb85d99e923ff57","size":109479329},{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:20aef84d8098d47a0643a2f99ce05f0deed957b3a259fb708c538f23ed97cc82","size":103996238}],"annotations":{"ws.tycho.stacker.git_version":"0.3.25"}}`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-test", "blobs/sha256", "45df53588e59759a12bd3eca553cdc9063939baac9a28d7ebb6101e4ec230b76"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprintf(`{"created": "2020-04-08T05:32:49.805795564Z","author": "","architecture": "amd64","os": "linux","config": {"Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]},"rootfs": {"type": "layers","diff_ids": []},"history": [{"created": "2020-05-11T18:17:24.516727354Z","created_by": "stacker umoci repack"}, {"created": "2020-04-08T05:08:53.213437118Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:12:15.999154739Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-05-11T19:30:02.467956112Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:20:38.068800557Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-04-08T05:21:01.956154957Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:32:24.582132274Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-04-08T05:32:49.805795564Z","created_by": "stacker build","author": "","empty_layer": true}]}`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-test", "blobs/sha256", "1fc1d045b241b04fea54333d76d4f57eb1961f9a314413f02a956b76e77a99f0"), content)
	if err != nil {
		return err
	}

	// Create a image with invalid layer blob

	err = os.MkdirAll(path.Join(dbDir, "zot-invalid-layer", "blobs/sha256"), 0o755)
	if err != nil {
		return err
	}

	content = fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb","size":886,"annotations":{"org.opencontainers.image.ref.name":"0.3.25"},"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:45df53588e59759a12bd3eca553cdc9063939baac9a28d7ebb6101e4ec230b76","size":873,"annotations":{"org.opencontainers.image.ref.name":"0.3.22-squashfs"},"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:71448405a4b89539fcfa581afb4dc7d257f98857686b8138b08a1c539f313099","size":886,"annotations":{"org.opencontainers.image.ref.name":"0.3.19"},"platform":{"architecture":"amd64","os":"linux"}}]}`)

	err = makeTestFile(path.Join(dbDir, "zot-invalid-layer", "index.json"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:5f00b5570a5561a6f9b7e66e4f26e2e30c4d09b43a8d3f993f3c1c99be6137a6","size":1740},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:f8b7e41ce10d9a0f614f068326c43431c2777e6fc346f729c2a643bfab24af83","size":59451113},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:9ca9274f196b56a708a7a672d3de88184c0158a30744d355dd0411f3a6850fa6","size":55685756},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:6c1ca50788f93937e9ce9341b564f86cbbcd28e367ed6a57cfc776aee4a9d050","size":113726186},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:d1a92139df86bdf00c818db75bf1ecc860857d142b426e9971a62f5f90e2aa57","size":108755643}],"annotations":{"ws.tycho.stacker.git_version":"0.3.25"}}`)

	err = makeTestFile(path.Join(dbDir, "zot-invalid-layer", "blobs/sha256", "eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprintf(`{"created":"2020-05-11T19:12:23.239785708Z","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","architecture":"amd64","os":"linux","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]},"rootfs":{"type":"layers","diff_ids":["sha256:8817d297aa60796f41f559ba688d29b31830854014091233575d474f3a6e808e","sha256:dd5a09481ae1f5caf8d1dbc87bc7f86a01af030796467ba25851ad69964d226d","sha256:a8bce2aaf5ce6f1a5459b72de64927a1e507a911453789bf60df06752222cacd","sha256:dc0b750a934e8f376af23de6dcab1af282967498844a6510aed2c61277f20c11"]},"history":[{"created":"2020-05-11T18:17:24.516727354Z","created_by":"stacker umoci repack"},{"created":"2020-05-11T18:17:33.111086359Z","created_by":"stacker build","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","empty_layer":true},{"created":"2020-05-11T18:18:43.147035914Z","created_by":"stacker umoci repack","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI"},{"created":"2020-05-11T18:19:03.346279546Z","created_by":"stacker build","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","empty_layer":true},{"created":"2020-05-11T18:27:01.623678656Z","created_by":"stacker umoci repack","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI"},{"created":"2020-05-11T18:27:23.420280147Z","created_by":"stacker build","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","empty_layer":true},{"created":"2020-05-11T19:11:54.886053615Z","created_by":"stacker umoci repack","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI"},{"created":"2020-05-11T19:12:23.239785708Z","created_by":"stacker build","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","empty_layer":true}]`)

	err = makeTestFile(path.Join(dbDir, "zot-invalid-layer", "blobs/sha256", "5f00b5570a5561a6f9b7e66e4f26e2e30c4d09b43a8d3f993f3c1c99be6137a6"), content)
	if err != nil {
		return err
	}

	// Create a image with no layer blob

	err = os.MkdirAll(path.Join(dbDir, "zot-no-layer", "blobs/sha256"), 0o755)
	if err != nil {
		return err
	}

	content = fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb","size":886,"annotations":{"org.opencontainers.image.ref.name":"0.3.25"},"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:45df53588e59759a12bd3eca553cdc9063939baac9a28d7ebb6101e4ec230b76","size":873,"annotations":{"org.opencontainers.image.ref.name":"0.3.22-squashfs"},"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:71448405a4b89539fcfa581afb4dc7d257f98857686b8138b08a1c539f313099","size":886,"annotations":{"org.opencontainers.image.ref.name":"0.3.19"},"platform":{"architecture":"amd64","os":"linux"}}]}`)

	err = makeTestFile(path.Join(dbDir, "zot-no-layer", "index.json"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:5f00b5570a5561a6f9b7e66e4f26e2e30c4d09b43a8d3f993f3c1c99be6137a6","size":1740},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:f8b7e41ce10d9a0f614f068326c43431c2777e6fc346f729c2a643bfab24af83","size":59451113},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:9ca9274f196b56a708a7a672d3de88184c0158a30744d355dd0411f3a6850fa6","size":55685756},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:6c1ca50788f93937e9ce9341b564f86cbbcd28e367ed6a57cfc776aee4a9d050","size":113726186},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:d1a92139df86bdf00c818db75bf1ecc860857d142b426e9971a62f5f90e2aa57","size":108755643}],"annotations":{"ws.tycho.stacker.git_version":"0.3.25"}}`)

	err = makeTestFile(path.Join(dbDir, "zot-no-layer", "blobs/sha256", "eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprintf(`{"created":"2020-05-11T19:12:23.239785708Z","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","architecture":"amd64","os":"linux","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]},"rootfs":{"type":"layers","diff_ids":["sha256:8817d297aa60796f41f559ba688d29b31830854014091233575d474f3a6e808e","sha256:dd5a09481ae1f5caf8d1dbc87bc7f86a01af030796467ba25851ad69964d226d","sha256:a8bce2aaf5ce6f1a5459b72de64927a1e507a911453789bf60df06752222cacd","sha256:dc0b750a934e8f376af23de6dcab1af282967498844a6510aed2c61277f20c11"]},"history":[{"created":"2020-05-11T18:17:24.516727354Z","created_by":"stacker umoci repack"},{"created":"2020-05-11T18:17:33.111086359Z","created_by":"stacker build","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","empty_layer":true},{"created":"2020-05-11T18:18:43.147035914Z","created_by":"stacker umoci repack","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI"},{"created":"2020-05-11T18:19:03.346279546Z","created_by":"stacker build","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","empty_layer":true},{"created":"2020-05-11T18:27:01.623678656Z","created_by":"stacker umoci repack","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI"},{"created":"2020-05-11T18:27:23.420280147Z","created_by":"stacker build","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","empty_layer":true},{"created":"2020-05-11T19:11:54.886053615Z","created_by":"stacker umoci repack","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI"},{"created":"2020-05-11T19:12:23.239785708Z","created_by":"stacker build","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","empty_layer":true}]`)

	err = makeTestFile(path.Join(dbDir, "zot-no-layer", "blobs/sha256", "5f00b5570a5561a6f9b7e66e4f26e2e30c4d09b43a8d3f993f3c1c99be6137a"), content)
	if err != nil {
		return err
	}

	return nil
}

func makeTestFile(fileName, content string) error {
	if err := os.WriteFile(fileName, []byte(content), 0o600); err != nil {
		panic(err)
	}

	return nil
}

func TestImageFormat(t *testing.T) {
	Convey("Test valid image", t, func() {
		log := log.NewLogger("debug", "")
		dbDir := "../../../../test/data"

		conf := config.New()
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Lint = &extconf.LintConfig{}

		metrics := monitoring.NewMetricsServer(false, log)
		defaultStore := local.NewImageStore(dbDir, false, storConstants.DefaultGCDelay,
			false, false, log, metrics, nil)
		storeController := storage.StoreController{DefaultStore: defaultStore}

		cveInfo := cveinfo.NewCVEInfo(storeController, log)

		isValidImage, err := cveInfo.Scanner.IsImageFormatScannable("zot-test")
		So(err, ShouldBeNil)
		So(isValidImage, ShouldEqual, true)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-test:0.0.1")
		So(err, ShouldBeNil)
		So(isValidImage, ShouldEqual, true)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-test:0.0.")
		So(err, ShouldBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-noindex-test")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot--tet")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-noindex-test")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-squashfs-noblobs")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-squashfs-invalid-index")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-squashfs-invalid-blob")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-squashfs-test:0.3.22-squashfs")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-nonreadable-test")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)
	})
}

func TestDownloadDB(t *testing.T) {
	Convey("Download DB passing invalid dir", t, func() {
		err := testSetup()
		So(err, ShouldBeNil)
	})
}

func TestCVESearch(t *testing.T) {
	Convey("Test image vulnerability scanning", t, func() {
		updateDuration, _ = time.ParseDuration("1h")
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		conf.Storage.RootDirectory = dbDir
		cveConfig := &extconf.CVEConfig{
			UpdateInterval: updateDuration,
		}
		defaultVal := true
		searchConfig := &extconf.SearchConfig{
			Enable: &defaultVal,
			CVE:    cveConfig,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		ctlr := api.NewController(conf)

		go func() {
			// this blocks
			if err := ctlr.Run(context.Background()); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(baseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		// Wait for trivy db to download
		time.Sleep(90 * time.Second)

		defer func() {
			ctx := context.Background()
			_ = ctlr.Server.Shutdown(ctx)
		}()

		// without creds, should get access error
		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
		var apiErr api.Error
		err = json.Unmarshal(resp.Body(), &apiErr)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + constants.ExtSearchPrefix)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
		err = json.Unmarshal(resp.Body(), &apiErr)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var cveResult CveResult
		err = json.Unmarshal(resp.Body(), &cveResult)
		So(err, ShouldBeNil)
		So(len(cveResult.ImgList.CVEResultForImage.CVEList), ShouldNotBeZeroValue)

		cvid := cveResult.ImgList.CVEResultForImage.CVEList[0].ID

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cvid + "\",image:\"zot-test\"){RepoName%20LastUpdated}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var imgListWithCVEFixed ImgListWithCVEFixed
		err = json.Unmarshal(resp.Body(), &imgListWithCVEFixed)
		So(err, ShouldBeNil)
		So(len(imgListWithCVEFixed.Images), ShouldEqual, 0)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cvid + "\",image:\"zot-cve-test\"){RepoName%20LastUpdated}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &imgListWithCVEFixed)
		So(err, ShouldBeNil)
		So(len(imgListWithCVEFixed.Images), ShouldEqual, 0)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cvid + "\",image:\"zot-test\"){RepoName%20LastUpdated}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"b/zot-squashfs-test:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var cveSquashFSResult CveResult
		err = json.Unmarshal(resp.Body(), &cveSquashFSResult)
		So(err, ShouldBeNil)
		So(len(cveSquashFSResult.ImgList.CVEResultForImage.CVEList), ShouldBeZeroValue)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"zot-squashfs-noindex:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cvid + "\",image:\"zot-squashfs-noindex\"){RepoName%20LastUpdated}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"zot-squashfs-invalid-index:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cvid + "\",image:\"zot-squashfs-invalid-index\"){RepoName%20LastUpdated}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"zot-squashfs-noblobs:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cvid + "\",image:\"zot-squashfs-noblob\"){RepoName%20LastUpdated}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cvid + "\",image:\"zot-squashfs-test\"){RepoName%20LastUpdated}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"zot-squashfs-invalid-blob:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cvid + "\",image:\"zot-squashfs-invalid-blob\"){RepoName%20LastUpdated}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"zot-squashfs-test\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"cntos\"){Tag%20CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={ImageListForCVE(id:\"CVE-201-20482\"){RepoName%20Tag}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"zot-test\"){Tag%20CVEList{Id%20Description}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){Tag}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Id%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Id%20Description}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Id}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Description}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// Testing Invalid Search URL
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){Ta%20CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={ImageListForCVE(tet:\"CVE-2018-20482\"){RepoName%20Tag}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={ImageistForCVE(id:\"CVE-2018-20482\"){RepoName%20Tag}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={ImageListForCVE(id:\"CVE-2018-20482\"){ame%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={CVEListForImage(reo:\"zot-test:1.0.0\"){Tag%20CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.ExtSearchPrefix + "?query={ImageListForCVE(id:\"" + cvid + "\"){RepoName%20Tag}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestCVEConfig(t *testing.T) {
	Convey("Verify CVE config", t, func() {
		conf := config.New()
		port := GetFreePort()
		conf.HTTP.Port = port
		baseURL := GetBaseURL(port)
		htpasswdPath := MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		ctlr := api.NewController(conf)

		firstDir := t.TempDir()

		secondDir := t.TempDir()

		err := CopyFiles("../../../../test/data", path.Join(secondDir, "a"))
		if err != nil {
			panic(err)
		}

		ctlr.Config.Storage.RootDirectory = firstDir
		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{
			RootDirectory: secondDir,
		}

		ctlr.Config.Storage.SubPaths = subPaths

		go func() {
			// this blocks
			if err := ctlr.Run(context.Background()); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(baseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		resp, _ := resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.RoutePrefix + "/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.RoutePrefix + constants.ExtCatalogPrefix)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/v2/a/zot-test/tags/list")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/v2/zot-test/tags/list")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		defer func() {
			ctx := context.Background()
			_ = ctlr.Server.Shutdown(ctx)
		}()
	})
}

func TestHTTPOptionsResponse(t *testing.T) {
	Convey("Test http options response", t, func() {
		conf := config.New()
		port := GetFreePort()
		conf.HTTP.Port = port
		baseURL := GetBaseURL(port)

		ctlr := api.NewController(conf)

		firstDir, err := os.MkdirTemp("", "oci-repo-test")
		if err != nil {
			panic(err)
		}

		secondDir, err := os.MkdirTemp("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(firstDir)
		defer os.RemoveAll(secondDir)

		err = CopyFiles("../../../../test/data", path.Join(secondDir, "a"))
		if err != nil {
			panic(err)
		}

		ctlr.Config.Storage.RootDirectory = firstDir
		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{
			RootDirectory: secondDir,
		}

		ctlr.Config.Storage.SubPaths = subPaths

		go func() {
			// this blocks
			if err := ctlr.Run(context.Background()); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(baseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		resp, _ := resty.R().Options(baseURL + constants.RoutePrefix + constants.ExtCatalogPrefix)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)

		defer func() {
			ctx := context.Background()
			_ = ctlr.Server.Shutdown(ctx)
		}()
	})
}

func TestCVEStruct(t *testing.T) {
	Convey("Unit test the CVE struct", t, func() {
		// Setup test image data in mock storage
		layoutUtils := mocks.OciLayoutUtilsMock{
			GetImageManifestsFn: func(repo string) ([]ispec.Descriptor, error) {
				// Valid image for scanning
				if repo == "repo1" { //nolint: goconst
					return []ispec.Descriptor{
						{
							MediaType: "application/vnd.oci.image.manifest.v1+json",
							Size:      int64(0),
							Annotations: map[string]string{
								ispec.AnnotationRefName: "0.1.0",
							},
							Digest: "abcc",
						},
						{
							MediaType: "application/vnd.oci.image.manifest.v1+json",
							Size:      int64(0),
							Annotations: map[string]string{
								ispec.AnnotationRefName: "1.0.0",
							},
							Digest: "abcd",
						},
						{
							MediaType: "application/vnd.oci.image.manifest.v1+json",
							Size:      int64(0),
							Annotations: map[string]string{
								ispec.AnnotationRefName: "1.1.0",
							},
							Digest: "abce",
						},
						{
							MediaType: "application/vnd.oci.image.manifest.v1+json",
							Size:      int64(0),
							Annotations: map[string]string{
								ispec.AnnotationRefName: "1.0.1",
							},
							Digest: "abcf",
						},
					}, nil
				}

				// Image with non-scannable blob
				if repo == "repo2" { //nolint: goconst
					return []ispec.Descriptor{
						{
							MediaType: "application/vnd.oci.image.manifest.v1+json",
							Size:      int64(0),
							Annotations: map[string]string{
								ispec.AnnotationRefName: "1.0.0",
							},
							Digest: "abcd",
						},
					}, nil
				}

				// By default the image is not found
				return nil, errors.ErrRepoNotFound
			},
			GetImageTagsWithTimestampFn: func(repo string) ([]common.TagInfo, error) {
				// Valid image for scanning
				if repo == "repo1" { //nolint: goconst
					return []common.TagInfo{
						{
							Name:      "0.1.0",
							Digest:    "abcc",
							Timestamp: time.Date(2008, 1, 1, 12, 0, 0, 0, time.UTC),
						},
						{
							Name:      "1.0.0",
							Digest:    "abcd",
							Timestamp: time.Date(2009, 1, 1, 12, 0, 0, 0, time.UTC),
						},
						{
							Name:      "1.1.0",
							Digest:    "abce",
							Timestamp: time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC),
						},
						{
							Name:      "1.0.1",
							Digest:    "abcf",
							Timestamp: time.Date(2011, 1, 1, 12, 0, 0, 0, time.UTC),
						},
					}, nil
				}

				// Image with non-scannable blob
				if repo == "repo2" { //nolint: goconst
					return []common.TagInfo{
						{
							Name:      "1.0.0",
							Digest:    "abcd",
							Timestamp: time.Date(2009, 1, 1, 12, 0, 0, 0, time.UTC),
						},
					}, nil
				}

				// By default do not return any tags
				return []common.TagInfo{}, errors.ErrRepoNotFound
			},
			GetImageBlobManifestFn: func(imageDir string, digest digest.Digest) (v1.Manifest, error) {
				// Valid image for scanning
				if imageDir == "repo1" { //nolint: goconst
					return v1.Manifest{
						Layers: []v1.Descriptor{
							{
								MediaType: regTypes.OCILayer,
								Size:      0,
								Digest:    v1.Hash{},
							},
						},
					}, nil
				}

				// Image with non-scannable blob
				if imageDir == "repo2" { //nolint: goconst
					return v1.Manifest{
						Layers: []v1.Descriptor{
							{
								MediaType: regTypes.OCIRestrictedLayer,
								Size:      0,
								Digest:    v1.Hash{},
							},
						},
					}, nil
				}

				return v1.Manifest{}, errors.ErrBlobNotFound
			},
		}

		severities := map[string]int{
			"UNKNOWN":  0,
			"LOW":      1,
			"MEDIUM":   2,
			"HIGH":     3,
			"CRITICAL": 4,
		}

		// Setup test CVE data in mock scanner
		scanner := mocks.CveScannerMock{
			ScanImageFn: func(image string) (map[string]cvemodel.CVE, error) {
				// Images in chronological order
				if image == "repo1:0.1.0" {
					return map[string]cvemodel.CVE{
						"CVE1": {
							ID:          "CVE1",
							Severity:    "MEDIUM",
							Title:       "Title CVE1",
							Description: "Description CVE1",
						},
					}, nil
				}

				if image == "repo1:1.0.0" {
					return map[string]cvemodel.CVE{
						"CVE1": {
							ID:          "CVE1",
							Severity:    "MEDIUM",
							Title:       "Title CVE1",
							Description: "Description CVE1",
						},
						"CVE2": {
							ID:          "CVE2",
							Severity:    "HIGH",
							Title:       "Title CVE2",
							Description: "Description CVE2",
						},
						"CVE3": {
							ID:          "CVE3",
							Severity:    "LOW",
							Title:       "Title CVE3",
							Description: "Description CVE3",
						},
					}, nil
				}

				if image == "repo1:1.1.0" {
					return map[string]cvemodel.CVE{
						"CVE3": {
							ID:          "CVE3",
							Severity:    "LOW",
							Title:       "Title CVE3",
							Description: "Description CVE3",
						},
					}, nil
				}

				// As a minor release on 1.0.0 banch
				// does not include all fixes published in 1.1.0
				if image == "repo1:1.0.1" {
					return map[string]cvemodel.CVE{
						"CVE1": {
							ID:          "CVE1",
							Severity:    "MEDIUM",
							Title:       "Title CVE1",
							Description: "Description CVE1",
						},
						"CVE3": {
							ID:          "CVE3",
							Severity:    "LOW",
							Title:       "Title CVE3",
							Description: "Description CVE3",
						},
					}, nil
				}

				// By default the image has no vulnerabilities
				return map[string]cvemodel.CVE{}, nil
			},
			CompareSeveritiesFn: func(severity1, severity2 string) int {
				return severities[severity2] - severities[severity1]
			},
			IsImageFormatScannableFn: func(image string) (bool, error) {
				// Almost same logic compared to actual Trivy specific implementation
				imageDir, inputTag := common.GetImageDirAndTag(image)

				manifests, err := layoutUtils.GetImageManifests(imageDir)
				if err != nil {
					return false, err
				}

				for _, manifest := range manifests {
					tag, ok := manifest.Annotations[ispec.AnnotationRefName]

					if ok && inputTag != "" && tag != inputTag {
						continue
					}

					blobManifest, err := layoutUtils.GetImageBlobManifest(imageDir, manifest.Digest)
					if err != nil {
						return false, err
					}

					imageLayers := blobManifest.Layers

					for _, imageLayer := range imageLayers {
						switch imageLayer.MediaType {
						case regTypes.OCILayer, regTypes.DockerLayer:
							return true, nil

						default:
							return false, errors.ErrScanNotSupported
						}
					}
				}

				return false, nil
			},
		}

		log := log.NewLogger("debug", "")

		Convey("Test GetCVESummaryForImage", func() {
			cveInfo := cveinfo.BaseCveInfo{Log: log, Scanner: scanner, LayoutUtils: layoutUtils}

			// Image is found
			cveSummary, err := cveInfo.GetCVESummaryForImage("repo1:0.1.0")
			So(err, ShouldBeNil)
			So(cveSummary.Count, ShouldEqual, 1)
			So(cveSummary.MaxSeverity, ShouldEqual, "MEDIUM")

			cveSummary, err = cveInfo.GetCVESummaryForImage("repo1:1.0.0")
			So(err, ShouldBeNil)
			So(cveSummary.Count, ShouldEqual, 3)
			So(cveSummary.MaxSeverity, ShouldEqual, "HIGH")

			cveSummary, err = cveInfo.GetCVESummaryForImage("repo1:1.0.1")
			So(err, ShouldBeNil)
			So(cveSummary.Count, ShouldEqual, 2)
			So(cveSummary.MaxSeverity, ShouldEqual, "MEDIUM")

			cveSummary, err = cveInfo.GetCVESummaryForImage("repo1:1.1.0")
			So(err, ShouldBeNil)
			So(cveSummary.Count, ShouldEqual, 1)
			So(cveSummary.MaxSeverity, ShouldEqual, "LOW")

			// Image is not scannable
			cveSummary, err = cveInfo.GetCVESummaryForImage("repo2:1.0.0")
			So(err, ShouldEqual, errors.ErrScanNotSupported)
			So(cveSummary.Count, ShouldEqual, 0)
			So(cveSummary.MaxSeverity, ShouldEqual, "UNKNOWN")

			// Image is not found
			cveSummary, err = cveInfo.GetCVESummaryForImage("repo3:1.0.0")
			So(err, ShouldEqual, errors.ErrRepoNotFound)
			So(cveSummary.Count, ShouldEqual, 0)
			So(cveSummary.MaxSeverity, ShouldEqual, "UNKNOWN")
		})

		Convey("Test GetCVEListForImage", func() {
			cveInfo := cveinfo.BaseCveInfo{Log: log, Scanner: scanner, LayoutUtils: layoutUtils}

			// Image is found
			cveMap, err := cveInfo.GetCVEListForImage("repo1:0.1.0")
			So(err, ShouldBeNil)
			So(len(cveMap), ShouldEqual, 1)
			So(cveMap, ShouldContainKey, "CVE1")
			So(cveMap, ShouldNotContainKey, "CVE2")
			So(cveMap, ShouldNotContainKey, "CVE3")

			cveMap, err = cveInfo.GetCVEListForImage("repo1:1.0.0")
			So(err, ShouldBeNil)
			So(len(cveMap), ShouldEqual, 3)
			So(cveMap, ShouldContainKey, "CVE1")
			So(cveMap, ShouldContainKey, "CVE2")
			So(cveMap, ShouldContainKey, "CVE3")

			cveMap, err = cveInfo.GetCVEListForImage("repo1:1.0.1")
			So(err, ShouldBeNil)
			So(len(cveMap), ShouldEqual, 2)
			So(cveMap, ShouldContainKey, "CVE1")
			So(cveMap, ShouldNotContainKey, "CVE2")
			So(cveMap, ShouldContainKey, "CVE3")

			cveMap, err = cveInfo.GetCVEListForImage("repo1:1.1.0")
			So(err, ShouldBeNil)
			So(len(cveMap), ShouldEqual, 1)
			So(cveMap, ShouldNotContainKey, "CVE1")
			So(cveMap, ShouldNotContainKey, "CVE2")
			So(cveMap, ShouldContainKey, "CVE3")

			// Image is not scannable
			cveMap, err = cveInfo.GetCVEListForImage("repo2:1.0.0")
			So(err, ShouldEqual, errors.ErrScanNotSupported)
			So(len(cveMap), ShouldEqual, 0)

			// Image is not found
			cveMap, err = cveInfo.GetCVEListForImage("repo3:1.0.0")
			So(err, ShouldEqual, errors.ErrRepoNotFound)
			So(len(cveMap), ShouldEqual, 0)
		})

		Convey("Test GetImageListWithCVEFixed", func() {
			cveInfo := cveinfo.BaseCveInfo{Log: log, Scanner: scanner, LayoutUtils: layoutUtils}

			// Image is found
			tagList, err := cveInfo.GetImageListWithCVEFixed("repo1", "CVE1")
			So(err, ShouldBeNil)
			So(len(tagList), ShouldEqual, 1)
			So(tagList[0].Name, ShouldEqual, "1.1.0")

			tagList, err = cveInfo.GetImageListWithCVEFixed("repo1", "CVE2")
			So(err, ShouldBeNil)
			So(len(tagList), ShouldEqual, 2)
			So(tagList[0].Name, ShouldEqual, "1.1.0")
			So(tagList[1].Name, ShouldEqual, "1.0.1")

			tagList, err = cveInfo.GetImageListWithCVEFixed("repo1", "CVE3")
			So(err, ShouldBeNil)
			// CVE3 is not present in 0.1.0, but that is older than all other
			// images where it is present. The rest of the images explicitly  have it.
			// This means we consider it not fixed in any image.
			So(len(tagList), ShouldEqual, 0)

			// Image is not scannable
			tagList, err = cveInfo.GetImageListWithCVEFixed("repo2", "CVE100")
			// CVE is not considered fixed as scan is not possible
			// but do not return an error
			So(err, ShouldBeNil)
			So(len(tagList), ShouldEqual, 0)

			// Image is not found
			tagList, err = cveInfo.GetImageListWithCVEFixed("repo3", "CVE101")
			So(err, ShouldEqual, errors.ErrRepoNotFound)
			So(len(tagList), ShouldEqual, 0)
		})

		Convey("Test GetImageListForCVE", func() {
			cveInfo := cveinfo.BaseCveInfo{Log: log, Scanner: scanner, LayoutUtils: layoutUtils}

			// Image is found
			imageInfoByCveList, err := cveInfo.GetImageListForCVE("repo1", "CVE1")
			So(err, ShouldBeNil)
			So(len(imageInfoByCveList), ShouldEqual, 3)
			So(imageInfoByCveList[0].Tag, ShouldEqual, "0.1.0")
			So(imageInfoByCveList[1].Tag, ShouldEqual, "1.0.0")
			So(imageInfoByCveList[2].Tag, ShouldEqual, "1.0.1")

			imageInfoByCveList, err = cveInfo.GetImageListForCVE("repo1", "CVE2")
			So(err, ShouldBeNil)
			So(len(imageInfoByCveList), ShouldEqual, 1)
			So(imageInfoByCveList[0].Tag, ShouldEqual, "1.0.0")

			imageInfoByCveList, err = cveInfo.GetImageListForCVE("repo1", "CVE3")
			So(err, ShouldBeNil)
			So(len(imageInfoByCveList), ShouldEqual, 3)
			So(imageInfoByCveList[0].Tag, ShouldEqual, "1.0.0")
			So(imageInfoByCveList[1].Tag, ShouldEqual, "1.1.0")
			So(imageInfoByCveList[2].Tag, ShouldEqual, "1.0.1")

			// Image is not scannable
			imageInfoByCveList, err = cveInfo.GetImageListForCVE("repo2", "CVE100")
			// Image is not considered affected with CVE as scan is not possible
			// but do not return an error
			So(err, ShouldBeNil)
			So(len(imageInfoByCveList), ShouldEqual, 0)

			// Image is not found
			imageInfoByCveList, err = cveInfo.GetImageListForCVE("repo3", "CVE101")
			So(err, ShouldEqual, errors.ErrRepoNotFound)
			So(len(imageInfoByCveList), ShouldEqual, 0)
		})

		Convey("Test errors while scanning", func() {
			localScanner := scanner

			localScanner.ScanImageFn = func(image string) (map[string]cvemodel.CVE, error) {
				// Could be any type of error, let's reuse this one
				return nil, errors.ErrScanNotSupported
			}

			cveInfo := cveinfo.BaseCveInfo{Log: log, Scanner: localScanner, LayoutUtils: layoutUtils}

			cveSummary, err := cveInfo.GetCVESummaryForImage("repo1:0.1.0")
			So(err, ShouldNotBeNil)
			So(cveSummary.Count, ShouldEqual, 0)
			So(cveSummary.MaxSeverity, ShouldEqual, "UNKNOWN")

			cveMap, err := cveInfo.GetCVEListForImage("repo1:0.1.0")
			So(err, ShouldNotBeNil)
			So(cveMap, ShouldBeNil)

			tagList, err := cveInfo.GetImageListWithCVEFixed("repo1", "CVE1")
			// CVE is not considered fixed as scan is not possible
			// but do not return an error
			So(err, ShouldBeNil)
			So(len(tagList), ShouldEqual, 0)

			imageInfoByCveList, err := cveInfo.GetImageListForCVE("repo1", "CVE1")
			// Image is not considered affected with CVE as scan is not possible
			// but do not return an error
			So(err, ShouldBeNil)
			So(len(imageInfoByCveList), ShouldEqual, 0)
		})

		Convey("Test error while reading blob manifest", func() {
			localLayoutUtils := layoutUtils
			localLayoutUtils.GetImageBlobManifestFn = func(imageDir string,
				digest digest.Digest,
			) (v1.Manifest, error) {
				return v1.Manifest{}, errors.ErrBlobNotFound
			}

			cveInfo := cveinfo.BaseCveInfo{Log: log, Scanner: scanner, LayoutUtils: localLayoutUtils}

			imageInfoByCveList, err := cveInfo.GetImageListForCVE("repo1", "CVE1")
			So(err, ShouldNotBeNil)
			So(len(imageInfoByCveList), ShouldEqual, 0)
		})
	})
}
