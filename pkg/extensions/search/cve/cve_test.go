// nolint: lll
package cveinfo_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	"github.com/anuvu/zot/pkg/api"
	ext "github.com/anuvu/zot/pkg/extensions"
	"github.com/anuvu/zot/pkg/extensions/search/common"
	cveinfo "github.com/anuvu/zot/pkg/extensions/search/cve"
	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/phayes/freeport"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
)

// nolint:gochecknoglobals
var (
	cve            *cveinfo.CveInfo
	dbDir          string
	updateDuration time.Duration
)

const (
	BaseURL    = "http://127.0.0.1:%s"
	username   = "test"
	passphrase = "test"
)

type CveResult struct {
	ImgList ImgList `json:"data"`
}

type ImgWithFixedCVE struct {
	ImgResults ImgResults `json:"data"`
}

type ImgResults struct {
	ImgResultForFixedCVE ImgResultForFixedCVE `json:"ImgResultForFixedCVE"`
}

type ImgResultForFixedCVE struct {
	Tags []TagInfo `json:"Tags"`
}

type TagInfo struct {
	Name      string
	Timestamp time.Time
}

type ImgList struct {
	CVEResultForImage CVEResultForImage `json:"CVEListForImage"`
}

type CVEResultForImage struct {
	Tag     string `json:"Tag"`
	CVEList []CVE  `json:"CVEList"`
}

type CVE struct {
	ID          string `json:"Id"`
	Description string `json:"Description"`
	Severity    string `json:"Severity"`
}

func getFreePort() string {
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(err)
	}

	return fmt.Sprint(port)
}

func getBaseURL(port string) string {
	return fmt.Sprintf(BaseURL, port)
}

func testSetup() error {
	dir, err := ioutil.TempDir("", "util_test")
	if err != nil {
		return err
	}

	log := log.NewLogger("debug", "")

	storeController := storage.StoreController{DefaultStore: storage.NewImageStore(dir, false, false, log)}

	layoutUtils := common.NewOciLayoutUtils(log)

	cve = &cveinfo.CveInfo{Log: log, StoreController: storeController, LayoutUtils: layoutUtils}

	dbDir = dir

	err = generateTestData()
	if err != nil {
		return err
	}

	err = copyFiles("../../../../test/data", dbDir)
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

	if err = ioutil.WriteFile(path.Join(dbDir, "zot-nonreadable-test", "index.json"), buf, 0o111); err != nil {
		return err
	}

	// Image dir with invalid index.json
	err = os.Mkdir(path.Join(dbDir, "zot-squashfs-invalid-index"), 0o755)
	if err != nil {
		return err
	}

	content := fmt.Sprintf(`{"schemaVersion": 2,"manifests"[{"mediaType": "application/vnd.oci.image.manifest.v1+json","digest": "sha256:2a9b097b4e4c613dd8185eba55163201a221909f3d430f8df87cd3639afc5929","size": 1240,"annotations": {"org.opencontainers.image.ref.name": "commit-aaa7c6e7-squashfs"},"platform": {"architecture": "amd64","os": "linux"}}]}`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-invalid-index", "index.json"), content)
	if err != nil {
		return err
	}

	// Image dir with no blobs
	err = os.Mkdir(path.Join(dbDir, "zot-squashfs-noblobs"), 0o755)
	if err != nil {
		return err
	}

	content = fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:2a9b097b4e4c613dd8185eba55163201a221909f3d430f8df87cd3639afc5929","size":1240,"annotations":{"org.opencontainers.image.ref.name":"commit-aaa7c6e7-squashfs"},"platform":{"architecture":"amd64","os":"linux"}}]}
	`)

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

	if err = ioutil.WriteFile(path.Join(dbDir, "zot-squashfs-test", "oci-layout"), buf, 0o644); err != nil { //nolint: gosec
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

func makeTestFile(fileName string, content string) error {
	if err := ioutil.WriteFile(fileName, []byte(content), 0o600); err != nil {
		panic(err)
	}

	return nil
}

func copyFiles(sourceDir string, destDir string) error {
	sourceMeta, err := os.Stat(sourceDir)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(destDir, sourceMeta.Mode()); err != nil {
		return err
	}

	files, err := ioutil.ReadDir(sourceDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		sourceFilePath := path.Join(sourceDir, file.Name())
		destFilePath := path.Join(destDir, file.Name())

		if file.IsDir() {
			if err = copyFiles(sourceFilePath, destFilePath); err != nil {
				return err
			}
		} else {
			sourceFile, err := os.Open(sourceFilePath)
			if err != nil {
				return err
			}
			defer sourceFile.Close()

			destFile, err := os.Create(destFilePath)
			if err != nil {
				return err
			}
			defer destFile.Close()

			if _, err = io.Copy(destFile, sourceFile); err != nil {
				return err
			}
		}
	}

	return nil
}

func makeHtpasswdFile() string {
	f, err := ioutil.TempFile("", "htpasswd-")
	if err != nil {
		panic(err)
	}

	// bcrypt(username="test", passwd="test")
	content := []byte("test:$2y$05$hlbSXDp6hzDLu6VwACS39ORvVRpr3OMR4RlJ31jtlaOEGnPjKZI1m\n")
	if err := ioutil.WriteFile(f.Name(), content, 0o600); err != nil {
		panic(err)
	}

	return f.Name()
}

func TestMultipleStoragePath(t *testing.T) {
	Convey("Test multiple storage path", t, func() {
		// Create temporary directory
		firstRootDir, err := ioutil.TempDir("", "util_test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(firstRootDir)

		secondRootDir, err := ioutil.TempDir("", "util_test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(secondRootDir)

		thirdRootDir, err := ioutil.TempDir("", "util_test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(thirdRootDir)

		log := log.NewLogger("debug", "")

		// Create ImageStore
		firstStore := storage.NewImageStore(firstRootDir, false, false, log)

		secondStore := storage.NewImageStore(secondRootDir, false, false, log)

		thirdStore := storage.NewImageStore(thirdRootDir, false, false, log)

		storeController := storage.StoreController{}

		storeController.DefaultStore = firstStore

		subStore := make(map[string]*storage.ImageStore)

		subStore["/a"] = secondStore
		subStore["/b"] = thirdStore

		storeController.SubStore = subStore

		cveInfo, err := cveinfo.GetCVEInfo(storeController, log)

		So(err, ShouldBeNil)
		So(cveInfo.StoreController.DefaultStore, ShouldNotBeNil)
		So(cveInfo.StoreController.SubStore, ShouldNotBeNil)
	})
}

func TestDownloadDB(t *testing.T) {
	Convey("Download DB passing invalid dir", t, func() {
		err := testSetup()
		So(err, ShouldBeNil)
		// Test Invalid dir download
		err = cveinfo.UpdateCVEDb("./testdata1", cve.Log)
		So(err, ShouldNotBeNil)
	})
}

func TestCVESearch(t *testing.T) {
	Convey("Test image vulenrability scanning", t, func() {
		updateDuration, _ = time.ParseDuration("1h")
		port := getFreePort()
		baseURL := getBaseURL(port)
		config := api.NewConfig()
		config.HTTP.Port = port
		htpasswdPath := makeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		config.HTTP.Auth = &api.AuthConfig{
			HTPasswd: api.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		c := api.NewController(config)
		c.Config.Storage.RootDirectory = dbDir
		cveConfig := &ext.CVEConfig{
			UpdateInterval: updateDuration,
		}
		searchConfig := &ext.SearchConfig{
			CVE:    cveConfig,
			Enable: true,
		}
		c.Config.Extensions = &ext.ExtensionConfig{
			Search: searchConfig,
		}
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
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
		time.Sleep(45 * time.Second)

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// without creds, should get access error
		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
		var e api.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + "/query/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"zot-test:0.0.1\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var cveResult CveResult
		err = json.Unmarshal(resp.Body(), &cveResult)
		So(err, ShouldBeNil)
		So(len(cveResult.ImgList.CVEResultForImage.CVEList), ShouldNotBeZeroValue)

		id := cveResult.ImgList.CVEResultForImage.CVEList[0].ID

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={ImageListWithCVEFixed(id:\"" + id + "\",image:\"zot-test\"){Tags{Name%20Timestamp}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var imgFixedCVEResult ImgWithFixedCVE
		err = json.Unmarshal(resp.Body(), &imgFixedCVEResult)
		So(err, ShouldBeNil)
		So(len(imgFixedCVEResult.ImgResults.ImgResultForFixedCVE.Tags), ShouldEqual, 0)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={ImageListWithCVEFixed(id:\"" + id + "\",image:\"zot-cve-test\"){Tags{Name%20Timestamp}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &imgFixedCVEResult)
		So(err, ShouldBeNil)
		So(len(imgFixedCVEResult.ImgResults.ImgResultForFixedCVE.Tags), ShouldEqual, 0)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={ImageListWithCVEFixed(id:\"" + id + "\",image:\"zot-test\"){Tags{Name%20Timestamp}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"zot-squashfs-test:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var cveSquashFSResult CveResult
		err = json.Unmarshal(resp.Body(), &cveSquashFSResult)
		So(err, ShouldBeNil)
		So(len(cveSquashFSResult.ImgList.CVEResultForImage.CVEList), ShouldBeZeroValue)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"zot-squashfs-noindex:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={ImageListWithCVEFixed(id:\"" + id + "\",image:\"zot-squashfs-noindex\"){Tags{Name%20Timestamp}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"zot-squashfs-invalid-index:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={ImageListWithCVEFixed(id:\"" + id + "\",image:\"zot-squashfs-invalid-index\"){Tags{Name%20Timestamp}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"zot-squashfs-noblobs:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={ImageListWithCVEFixed(id:\"" + id + "\",image:\"zot-squashfs-noblob\"){Tags{Name%20Timestamp}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={ImageListWithCVEFixed(id:\"" + id + "\",image:\"zot-squashfs-test\"){Tags{Name%20Timestamp}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"zot-squashfs-invalid-blob:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={ImageListWithCVEFixed(id:\"" + id + "\",image:\"zot-squashfs-invalid-blob\"){Tags{Name%20Timestamp}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"zot-squashfs-test\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"cntos\"){Tag%20CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={ImageListForCVE(id:\"CVE-201-20482\"){Name%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"zot-test\"){Tag%20CVEList{Id%20Description}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"zot-test:0.0.1\"){Tag}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Id%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Id%20Description}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Id}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Description}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// Testing Invalid Search URL
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(image:\"zot-test:0.0.1\"){Ta%20CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={ImageListForCVE(tet:\"CVE-2018-20482\"){Name%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={ImageistForCVE(id:\"CVE-2018-20482\"){Name%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={ImageListForCVE(id:\"CVE-2018-20482\"){ame%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={CVEListForImage(reo:\"zot-test:1.0.0\"){Tag%20CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/query?query={ImageListForCVE(id:\"" + id + "\"){Name%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestCVEConfig(t *testing.T) {
	Convey("Verify CVE config", t, func() {
		config := api.NewConfig()
		port := config.HTTP.Port
		baseURL := getBaseURL(port)
		htpasswdPath := makeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		config.HTTP.Auth = &api.AuthConfig{
			HTPasswd: api.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		c := api.NewController(config)
		firstDir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}

		secondDir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(firstDir)
		defer os.RemoveAll(secondDir)

		err = copyFiles("../../../../test/data", path.Join(secondDir, "a"))
		if err != nil {
			panic(err)
		}

		c.Config.Storage.RootDirectory = firstDir
		subPaths := make(map[string]api.StorageConfig)
		subPaths["/a"] = api.StorageConfig{
			RootDirectory: secondDir,
		}
		c.Config.Storage.SubPaths = subPaths

		go func() {
			// this blocks
			if err := c.Run(); err != nil {
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

		resp, _ := resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/v2/_catalog")
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
			_ = c.Server.Shutdown(ctx)
		}()
	})
}
