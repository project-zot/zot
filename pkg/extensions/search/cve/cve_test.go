//go:build search
// +build search

//nolint:lll,gosimple
package cveinfo_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	regTypes "github.com/google/go-containerregistry/pkg/v1/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	apiErr "zotregistry.dev/zot/pkg/api/errors"
	zcommon "zotregistry.dev/zot/pkg/common"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	cveinfo "zotregistry.dev/zot/pkg/extensions/search/cve"
	cvecache "zotregistry.dev/zot/pkg/extensions/search/cve/cache"
	cvemodel "zotregistry.dev/zot/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta"
	"zotregistry.dev/zot/pkg/meta/boltdb"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/local"
	test "zotregistry.dev/zot/pkg/test/common"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/mocks"
	ociutils "zotregistry.dev/zot/pkg/test/oci-utils"
)

type CveResult struct {
	ImgList ImgList    `json:"data"`
	Errors  []ErrorGQL `json:"errors"`
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

type ErrorGQL struct {
	Message string   `json:"message"`
	Path    []string `json:"path"`
}

//nolint:tagliatelle // graphQL schema
type CVEResultForImage struct {
	Tag     string         `json:"Tag"`
	CVEList []cvemodel.CVE `json:"CVEList"`
}

func testSetup(t *testing.T) (string, error) {
	t.Helper()
	dir := t.TempDir()

	err := generateTestData(dir)
	if err != nil {
		return "", err
	}

	testStorageCtrl := ociutils.GetDefaultStoreController(dir, log.NewLogger("debug", ""))

	err = WriteImageToFileSystem(CreateRandomVulnerableImage(), "zot-test", "0.0.1", testStorageCtrl)
	if err != nil {
		return "", err
	}

	err = WriteImageToFileSystem(CreateRandomVulnerableImage(), "zot-cve-test", "0.0.1", testStorageCtrl)
	if err != nil {
		return "", err
	}

	return dir, nil
}

func generateTestData(dbDir string) error { //nolint: gocyclo
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

	if err = os.WriteFile(path.Join(dbDir, "zot-nonreadable-test", "index.json"), //nolint:gosec // test code
		buf, 0o111); err != nil {
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

	content = fmt.Sprint(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:2a9b097b4e4c613dd8185eba55163201a221909f3d430f8df87cd3639afc5929","size":1240,"annotations":{"org.opencontainers.image.ref.name":"commit-aaa7c6e7-squashfs"},"platform":{"architecture":"amd64","os":"linux"}}]}
	`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-invalid-blob", "index.json"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprint(`{"schemaVersion":2,"config"{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:4b37d4133908ac9a3032ba996020f2ad41354a616b071ca7e726a1df18a0f354","size":1691},"layers":[{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:a01a66356aace53222e92fb6fd990b23eb44ab0e58dff6f853fa9f771ecf3ac5","size":54996992},{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:91c26d6934ef2b5c5c4d8458af9bfc4ca46cf90c22380193154964abc8298a7a","size":52330496},{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:f281a550ca49746cfc6b8f1ac52f8086b3d5845db2ca18fde980dab62ae3bf7d","size":23343104},{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:7ee02568717acdda336c9d56d4dc6ea7f3b1c553e43bb0c0ecc6fd3bbd059d1a","size":5910528},{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:8fb33b130588b239235dedd560cdf49d29bbf6f2db5419ac68e4592a85c1f416","size":123269120},{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:1b49f0b33d4a696bb94d84c9acab3623e2c195bfb446d446a583a2f9f27b04c3","size":113901568}],"annotations":{"com.cisco.stacker.git_version":"7-dev19-63-gaaa7c6e7","ws.tycho.stacker.git_version":"0.3.26"}}
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

	content = fmt.Sprint(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb","size":886,"annotations":{"org.opencontainers.image.ref.name":"0.3.25"},"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:45df53588e59759a12bd3eca553cdc9063939baac9a28d7ebb6101e4ec230b76","size":873,"annotations":{"org.opencontainers.image.ref.name":"0.3.22-squashfs"},"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:71448405a4b89539fcfa581afb4dc7d257f98857686b8138b08a1c539f313099","size":886,"annotations":{"org.opencontainers.image.ref.name":"0.3.19"},"platform":{"architecture":"amd64","os":"linux"}}]}`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-test", "index.json"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprint(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:c5c2fd2b07ad4cb025cf20936d6bce6085584b8377780599be4da8a91739f0e8","size":1738},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:3414b5ef0ad2f0390daaf55b63c422eeedef6191d47036a69d8ee396fabdce72","size":58993484},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:a3b04fff744c13dfa4883e01fa35e01af8daa7f72d9e9b6b7fad1f28843846b6","size":55631733},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:754f517f58f302190aa94e025c25890c18e1e811127aed1ef25c189278ec4ab0","size":113612795},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:ec004cd43488b803d6e232599e83a3164394d44fcd9f44755fed7b5791087ede","size":108889651}],"annotations":{"ws.tycho.stacker.git_version":"0.3.19"}}`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-test", "blobs/sha256", "71448405a4b89539fcfa581afb4dc7d257f98857686b8138b08a1c539f313099"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprint(`{"created": "2020-04-08T05:32:49.805795564Z","author": "","architecture": "amd64","os": "linux","config": {"Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]},"rootfs": {"type": "layers","diff_ids": []},"history": [{"created": "2020-04-08T05:08:43.590117872Z","created_by": "stacker umoci repack"}, {"created": "2020-04-08T05:08:53.213437118Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:12:15.999154739Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-04-08T05:12:31.0513552Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:20:38.068800557Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-04-08T05:21:01.956154957Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:32:24.582132274Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-04-08T05:32:49.805795564Z","created_by": "stacker build","author": "","empty_layer": true}]}`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-test", "blobs/sha256", "c5c2fd2b07ad4cb025cf20936d6bce6085584b8377780599be4da8a91739f0e8"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprint(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:5f00b5570a5561a6f9b7e66e4f26e2e30c4d09b43a8d3f993f3c1c99be6137a6","size":1740},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:f8b7e41ce10d9a0f614f068326c43431c2777e6fc346f729c2a643bfab24af83","size":59451113},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:9ca9274f196b56a708a7a672d3de88184c0158a30744d355dd0411f3a6850fa6","size":55685756},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:6c1ca50788f93937e9ce9341b564f86cbbcd28e367ed6a57cfc776aee4a9d050","size":113726186},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:d1a92139df86bdf00c818db75bf1ecc860857d142b426e9971a62f5f90e2aa57","size":108755643}],"annotations":{"ws.tycho.stacker.git_version":"0.3.25"}}`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-test", "blobs/sha256", "eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprint(`{"created": "2020-04-08T05:32:49.805795564Z","author": "","architecture": "amd64","os": "linux","config": {"Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]},"rootfs": {"type": "layers","diff_ids": []},"history": [{"created": "2020-05-11T18:17:24.516727354Z","created_by": "stacker umoci repack"}, {"created": "2020-04-08T05:08:53.213437118Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:12:15.999154739Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-04-08T05:12:31.0513552Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:20:38.068800557Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-04-08T05:21:01.956154957Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:32:24.582132274Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-04-08T05:32:49.805795564Z","created_by": "stacker build","author": "","empty_layer": true}]}`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-test", "blobs/sha256", "5f00b5570a5561a6f9b7e66e4f26e2e30c4d09b43a8d3f993f3c1c99be6137a6"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprint(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:1fc1d045b241b04fea54333d76d4f57eb1961f9a314413f02a956b76e77a99f0","size":1218},"layers":[{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:c40d72b1556293c00a3e4b6c64c46ef4c7ae4d876dc18bad942b7d1903e8e5b7","size":54745420},{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:4115890e3e2563e545e03f264bfecb0097e24e02306ae3e7668dea52e00c6cc2","size":52213357},{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:91859e13e0cf704d5405199d73a2d1a0718391dbb183a77c4cb85d99e923ff57","size":109479329},{"mediaType":"application/vnd.oci.image.layer.squashfs","digest":"sha256:20aef84d8098d47a0643a2f99ce05f0deed957b3a259fb708c538f23ed97cc82","size":103996238}],"annotations":{"ws.tycho.stacker.git_version":"0.3.25"}}`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-test", "blobs/sha256", "45df53588e59759a12bd3eca553cdc9063939baac9a28d7ebb6101e4ec230b76"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprint(`{"created": "2020-04-08T05:32:49.805795564Z","author": "","architecture": "amd64","os": "linux","config": {"Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]},"rootfs": {"type": "layers","diff_ids": []},"history": [{"created": "2020-05-11T18:17:24.516727354Z","created_by": "stacker umoci repack"}, {"created": "2020-04-08T05:08:53.213437118Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:12:15.999154739Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-05-11T19:30:02.467956112Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:20:38.068800557Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-04-08T05:21:01.956154957Z","created_by": "stacker build","author": "","empty_layer": true}, {"created": "2020-04-08T05:32:24.582132274Z","created_by": "stacker umoci repack","author": ""}, {"created": "2020-04-08T05:32:49.805795564Z","created_by": "stacker build","author": "","empty_layer": true}]}`)

	err = makeTestFile(path.Join(dbDir, "zot-squashfs-test", "blobs/sha256", "1fc1d045b241b04fea54333d76d4f57eb1961f9a314413f02a956b76e77a99f0"), content)
	if err != nil {
		return err
	}

	// Create a image with invalid layer blob

	err = os.MkdirAll(path.Join(dbDir, "zot-invalid-layer", "blobs/sha256"), 0o755)
	if err != nil {
		return err
	}

	content = fmt.Sprint(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb","size":886,"annotations":{"org.opencontainers.image.ref.name":"0.3.25"},"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:45df53588e59759a12bd3eca553cdc9063939baac9a28d7ebb6101e4ec230b76","size":873,"annotations":{"org.opencontainers.image.ref.name":"0.3.22-squashfs"},"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:71448405a4b89539fcfa581afb4dc7d257f98857686b8138b08a1c539f313099","size":886,"annotations":{"org.opencontainers.image.ref.name":"0.3.19"},"platform":{"architecture":"amd64","os":"linux"}}]}`)

	err = makeTestFile(path.Join(dbDir, "zot-invalid-layer", "index.json"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprint(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:5f00b5570a5561a6f9b7e66e4f26e2e30c4d09b43a8d3f993f3c1c99be6137a6","size":1740},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:f8b7e41ce10d9a0f614f068326c43431c2777e6fc346f729c2a643bfab24af83","size":59451113},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:9ca9274f196b56a708a7a672d3de88184c0158a30744d355dd0411f3a6850fa6","size":55685756},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:6c1ca50788f93937e9ce9341b564f86cbbcd28e367ed6a57cfc776aee4a9d050","size":113726186},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:d1a92139df86bdf00c818db75bf1ecc860857d142b426e9971a62f5f90e2aa57","size":108755643}],"annotations":{"ws.tycho.stacker.git_version":"0.3.25"}}`)

	err = makeTestFile(path.Join(dbDir, "zot-invalid-layer", "blobs/sha256", "eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprint(`{"created":"2020-05-11T19:12:23.239785708Z","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","architecture":"amd64","os":"linux","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]},"rootfs":{"type":"layers","diff_ids":["sha256:8817d297aa60796f41f559ba688d29b31830854014091233575d474f3a6e808e","sha256:dd5a09481ae1f5caf8d1dbc87bc7f86a01af030796467ba25851ad69964d226d","sha256:a8bce2aaf5ce6f1a5459b72de64927a1e507a911453789bf60df06752222cacd","sha256:dc0b750a934e8f376af23de6dcab1af282967498844a6510aed2c61277f20c11"]},"history":[{"created":"2020-05-11T18:17:24.516727354Z","created_by":"stacker umoci repack"},{"created":"2020-05-11T18:17:33.111086359Z","created_by":"stacker build","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","empty_layer":true},{"created":"2020-05-11T18:18:43.147035914Z","created_by":"stacker umoci repack","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI"},{"created":"2020-05-11T18:19:03.346279546Z","created_by":"stacker build","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","empty_layer":true},{"created":"2020-05-11T18:27:01.623678656Z","created_by":"stacker umoci repack","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI"},{"created":"2020-05-11T18:27:23.420280147Z","created_by":"stacker build","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","empty_layer":true},{"created":"2020-05-11T19:11:54.886053615Z","created_by":"stacker umoci repack","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI"},{"created":"2020-05-11T19:12:23.239785708Z","created_by":"stacker build","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","empty_layer":true}]`)

	err = makeTestFile(path.Join(dbDir, "zot-invalid-layer", "blobs/sha256", "5f00b5570a5561a6f9b7e66e4f26e2e30c4d09b43a8d3f993f3c1c99be6137a6"), content)
	if err != nil {
		return err
	}

	// Create a image with no layer blob

	err = os.MkdirAll(path.Join(dbDir, "zot-no-layer", "blobs/sha256"), 0o755)
	if err != nil {
		return err
	}

	content = fmt.Sprint(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb","size":886,"annotations":{"org.opencontainers.image.ref.name":"0.3.25"},"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:45df53588e59759a12bd3eca553cdc9063939baac9a28d7ebb6101e4ec230b76","size":873,"annotations":{"org.opencontainers.image.ref.name":"0.3.22-squashfs"},"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:71448405a4b89539fcfa581afb4dc7d257f98857686b8138b08a1c539f313099","size":886,"annotations":{"org.opencontainers.image.ref.name":"0.3.19"},"platform":{"architecture":"amd64","os":"linux"}}]}`)

	err = makeTestFile(path.Join(dbDir, "zot-no-layer", "index.json"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprint(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:5f00b5570a5561a6f9b7e66e4f26e2e30c4d09b43a8d3f993f3c1c99be6137a6","size":1740},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:f8b7e41ce10d9a0f614f068326c43431c2777e6fc346f729c2a643bfab24af83","size":59451113},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:9ca9274f196b56a708a7a672d3de88184c0158a30744d355dd0411f3a6850fa6","size":55685756},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:6c1ca50788f93937e9ce9341b564f86cbbcd28e367ed6a57cfc776aee4a9d050","size":113726186},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:d1a92139df86bdf00c818db75bf1ecc860857d142b426e9971a62f5f90e2aa57","size":108755643}],"annotations":{"ws.tycho.stacker.git_version":"0.3.25"}}`)

	err = makeTestFile(path.Join(dbDir, "zot-no-layer", "blobs/sha256", "eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb"), content)
	if err != nil {
		return err
	}

	content = fmt.Sprint(`{"created":"2020-05-11T19:12:23.239785708Z","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","architecture":"amd64","os":"linux","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]},"rootfs":{"type":"layers","diff_ids":["sha256:8817d297aa60796f41f559ba688d29b31830854014091233575d474f3a6e808e","sha256:dd5a09481ae1f5caf8d1dbc87bc7f86a01af030796467ba25851ad69964d226d","sha256:a8bce2aaf5ce6f1a5459b72de64927a1e507a911453789bf60df06752222cacd","sha256:dc0b750a934e8f376af23de6dcab1af282967498844a6510aed2c61277f20c11"]},"history":[{"created":"2020-05-11T18:17:24.516727354Z","created_by":"stacker umoci repack"},{"created":"2020-05-11T18:17:33.111086359Z","created_by":"stacker build","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","empty_layer":true},{"created":"2020-05-11T18:18:43.147035914Z","created_by":"stacker umoci repack","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI"},{"created":"2020-05-11T18:19:03.346279546Z","created_by":"stacker build","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","empty_layer":true},{"created":"2020-05-11T18:27:01.623678656Z","created_by":"stacker umoci repack","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI"},{"created":"2020-05-11T18:27:23.420280147Z","created_by":"stacker build","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","empty_layer":true},{"created":"2020-05-11T19:11:54.886053615Z","created_by":"stacker umoci repack","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI"},{"created":"2020-05-11T19:12:23.239785708Z","created_by":"stacker build","author":"root@jenkinsProduction-Atom-Full-Build-c3-master-159CI","empty_layer":true}]`)

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
		imgDir := "../../../../test/data"
		dbDir := t.TempDir()

		metrics := monitoring.NewMetricsServer(false, log)
		defaultStore := local.NewImageStore(imgDir, false, false, log, metrics, nil, nil)
		storeController := storage.StoreController{DefaultStore: defaultStore}

		params := boltdb.DBParameters{
			RootDir: dbDir,
		}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log)
		So(err, ShouldBeNil)

		err = meta.ParseStorage(metaDB, storeController, log)
		So(err, ShouldBeNil)

		scanner := cveinfo.NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db", "", log)

		isValidImage, err := scanner.IsImageFormatScannable("zot-test", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = scanner.IsImageFormatScannable("zot-test", "0.0.1")
		So(err, ShouldBeNil)
		So(isValidImage, ShouldEqual, true)

		isValidImage, err = scanner.IsImageFormatScannable("zot-test", "0.0.")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = scanner.IsImageFormatScannable("zot-noindex-test", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = scanner.IsImageFormatScannable("zot--tet", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = scanner.IsImageFormatScannable("zot-noindex-test", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = scanner.IsImageFormatScannable("zot-squashfs-noblobs", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = scanner.IsImageFormatScannable("zot-squashfs-invalid-index", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = scanner.IsImageFormatScannable("zot-squashfs-invalid-blob", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = scanner.IsImageFormatScannable("zot-squashfs-test:0.3.22-squashfs", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = scanner.IsImageFormatScannable("zot-nonreadable-test", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)
	})

	Convey("isIndexScanable", t, func() {
		log := log.NewLogger("debug", "")

		metaDB := &mocks.MetaDBMock{
			GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
				return mTypes.RepoMeta{
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"tag": {
							MediaType: ispec.MediaTypeImageIndex,
							Digest:    godigest.FromString("digest").String(),
						},
					},
				}, nil
			},
			GetImageMetaFn: func(digest godigest.Digest) (mTypes.ImageMeta, error) {
				return mTypes.ImageMeta{
					MediaType: ispec.MediaTypeImageIndex,
					Digest:    godigest.FromString("digest"),
					Index:     &ispec.Index{},
				}, nil
			},
		}
		storeController := storage.StoreController{
			DefaultStore: mocks.MockedImageStore{},
		}

		scanner := cveinfo.NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db", "", log)

		isScanable, err := scanner.IsImageFormatScannable("repo", "tag")
		So(err, ShouldBeNil)
		So(isScanable, ShouldBeTrue)
	})
}

func TestCVESearchDisabled(t *testing.T) {
	Convey("Test with CVE search disabled", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		dbDir := t.TempDir()

		conf.Storage.RootDirectory = dbDir
		defaultVal := true
		searchConfig := &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
		if err != nil {
			panic(err)
		}

		logPath := logFile.Name()
		defer os.Remove(logPath)

		writers := io.MultiWriter(os.Stdout, logFile)

		ctlr := api.NewController(conf)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")
		ctlr.Log.Logger = ctlr.Log.Output(writers)
		ctrlManager := test.NewControllerManager(ctlr)

		ctrlManager.StartAndWait(port)

		// Wait for trivy db to download
		found, err := test.ReadLogFileAndSearchString(logPath, "cve config not provided, skipping cve-db update", 90*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		defer ctrlManager.StopServer()

		resp, _ := resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(string(resp.Body()), ShouldContainSubstring, "cve search is disabled")
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListForCVE(id:\"CVE-201-20482\"){Results{RepoName%20Tag}}}")
		So(string(resp.Body()), ShouldContainSubstring, "cve search is disabled")
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + "randomId" + "\",image:\"zot-test\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(string(resp.Body()), ShouldContainSubstring, "cve search is disabled")
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestCVESearch(t *testing.T) {
	Convey("Test image vulnerability scanning", t, func() {
		updateDuration, _ := time.ParseDuration("1h")
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)

		dbDir, err := testSetup(t)
		So(err, ShouldBeNil)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		conf.Storage.RootDirectory = dbDir

		trivyConfig := &extconf.TrivyConfig{
			DBRepository: "ghcr.io/project-zot/trivy-db",
		}
		cveConfig := &extconf.CVEConfig{
			UpdateInterval: updateDuration,
			Trivy:          trivyConfig,
		}
		defaultVal := true
		searchConfig := &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			CVE:        cveConfig,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
		if err != nil {
			panic(err)
		}

		logPath := logFile.Name()
		defer os.Remove(logPath)

		writers := io.MultiWriter(os.Stdout, logFile)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")
		ctrlManager := test.NewControllerManager(ctlr)

		ctrlManager.StartAndWait(port)

		// trivy db download fail
		err = os.Mkdir(dbDir+"/_trivy", 0o000)
		So(err, ShouldBeNil)
		found, err := test.ReadLogFileAndSearchString(logPath, "failed to download trivy-db to destination dir", 180*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		err = os.Chmod(dbDir+"/_trivy", 0o755)
		So(err, ShouldBeNil)

		// Wait for trivy db to download
		found, err = test.ReadLogFileAndSearchString(logPath, "cve-db update completed, next update scheduled after interval", 180*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		defer ctrlManager.StopServer()

		// without creds, should get access error
		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
		var apiErr apiErr.Error
		err = json.Unmarshal(resp.Body(), &apiErr)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + constants.FullSearchPrefix)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
		err = json.Unmarshal(resp.Body(), &apiErr)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		var cveResult CveResult
		contains := false
		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		err = json.Unmarshal(resp.Body(), &cveResult)
		So(err, ShouldBeNil)
		for _, err := range cveResult.Errors {
			result := strings.Contains(err.Message, "no reference provided")
			if result {
				contains = result
			}
		}
		So(contains, ShouldBeTrue)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &cveResult)
		So(err, ShouldBeNil)
		So(len(cveResult.ImgList.CVEResultForImage.CVEList), ShouldNotBeZeroValue)

		cveid := cveResult.ImgList.CVEResultForImage.CVEList[0].ID

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cveid + "\",image:\"zot-test\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var imgListWithCVEFixed ImgListWithCVEFixed
		err = json.Unmarshal(resp.Body(), &imgListWithCVEFixed)
		So(err, ShouldBeNil)
		So(len(imgListWithCVEFixed.Images), ShouldEqual, 0)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cveid + "\",image:\"zot-cve-test\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &imgListWithCVEFixed)
		So(err, ShouldBeNil)
		So(len(imgListWithCVEFixed.Images), ShouldEqual, 0)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cveid + "\",image:\"zot-test\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"b/zot-squashfs-test:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var cveSquashFSResult CveResult
		err = json.Unmarshal(resp.Body(), &cveSquashFSResult)
		So(err, ShouldBeNil)
		So(len(cveSquashFSResult.ImgList.CVEResultForImage.CVEList), ShouldBeZeroValue)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-squashfs-noindex:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cveid + "\",image:\"zot-squashfs-noindex\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-squashfs-invalid-index:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cveid + "\",image:\"zot-squashfs-invalid-index\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-squashfs-noblobs:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cveid + "\",image:\"zot-squashfs-noblob\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cveid + "\",image:\"zot-squashfs-test\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-squashfs-invalid-blob:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cveid + "\",image:\"zot-squashfs-invalid-blob\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-squashfs-test\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"cntos\"){Tag%20CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListForCVE(id:\"CVE-201-20482\"){Results{RepoName%20Tag}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test\"){Tag%20CVEList{Id%20Description}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){Tag}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Id%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Id%20Description}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Id}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Description}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// Testing Invalid Search URL
		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){Ta%20CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListForCVE(tet:\"CVE-2018-20482\"){Results{RepoName%20Tag}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={ImageistForCVE(id:\"CVE-2018-20482\"){Results{RepoName%20Tag}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListForCVE(id:\"CVE-2018-20482\"){ame%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(reo:\"zot-test:1.0.0\"){Tag%20CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListForCVE(id:\"" + cveid + "\"){Results{RepoName%20Tag}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestCVEStruct(t *testing.T) { //nolint:gocyclo
	Convey("Unit test the CVE struct", t, func() {
		const repo1 = "repo1"
		const repo2 = "repo2"
		const repo3 = "repo3"
		const repo4 = "repo4"
		const repo5 = "repo5"
		const repo6 = "repo6"
		const repo7 = "repo7"
		const repo8 = "repo8"
		const repo100 = "repo100"
		const repoMultiarch = "repoIndex"

		params := boltdb.DBParameters{
			RootDir: t.TempDir(),
		}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		// Create metadb data for scannable image with vulnerabilities
		image11 := CreateImageWith().DefaultLayers().
			ImageConfig(ispec.Image{Created: DateRef(2008, 1, 1, 12, 0, 0, 0, time.UTC)}).Build()

		err = metaDB.SetRepoReference(context.Background(), repo1, "0.1.0", image11.AsImageMeta())
		So(err, ShouldBeNil)

		image12 := CreateImageWith().DefaultLayers().
			ImageConfig(ispec.Image{Created: DateRef(2009, 1, 1, 12, 0, 0, 0, time.UTC)}).Build()

		err = metaDB.SetRepoReference(context.Background(), repo1, "1.0.0", image12.AsImageMeta())
		So(err, ShouldBeNil)

		image13 := CreateImageWith().DefaultLayers().
			ImageConfig(ispec.Image{Created: DateRef(2010, 1, 1, 12, 0, 0, 0, time.UTC)}).Build()

		err = metaDB.SetRepoReference(context.Background(), repo1, "1.1.0", image13.AsImageMeta())
		So(err, ShouldBeNil)

		image14 := CreateImageWith().DefaultLayers().
			ImageConfig(ispec.Image{Created: DateRef(2011, 1, 1, 12, 0, 0, 0, time.UTC)}).Build()

		err = metaDB.SetRepoReference(context.Background(), repo1, "1.0.1", image14.AsImageMeta())
		So(err, ShouldBeNil)

		// Create metadb data for scannable image with no vulnerabilities
		image61 := CreateImageWith().DefaultLayers().
			ImageConfig(ispec.Image{Created: DateRef(2016, 1, 1, 12, 0, 0, 0, time.UTC)}).Build()

		err = metaDB.SetRepoReference(context.Background(), repo6, "1.0.0", image61.AsImageMeta())
		So(err, ShouldBeNil)

		// Create metadb data for image not supporting scanning
		image21 := CreateImageWith().Layers([]Layer{{
			MediaType: ispec.MediaTypeImageLayerNonDistributableGzip, //nolint:staticcheck
			Blob:      []byte{10, 10, 10},
			Digest:    godigest.FromBytes([]byte{10, 10, 10}),
		}}).ImageConfig(ispec.Image{Created: DateRef(2009, 1, 1, 12, 0, 0, 0, time.UTC)}).Build()

		err = metaDB.SetRepoReference(context.Background(), repo2, "1.0.0", image21.AsImageMeta())
		So(err, ShouldBeNil)

		// Create metadb data for invalid images/negative tests
		image := CreateRandomImage()
		err = metaDB.SetRepoReference(context.Background(), repo3, "invalid-manifest", image.AsImageMeta())
		So(err, ShouldBeNil)

		image41 := CreateImageWith().DefaultLayers().
			CustomConfigBlob([]byte("invalid config blob"), ispec.MediaTypeImageConfig).Build()

		err = metaDB.SetRepoReference(context.Background(), repo4, "invalid-config", image41.AsImageMeta())
		So(err, ShouldBeNil)

		digest51 := godigest.FromString("abc8")
		randomImgData := CreateRandomImage().AsImageMeta()
		randomImgData.Digest = digest51
		randomImgData.Manifests[0].Digest = digest51
		err = metaDB.SetRepoReference(context.Background(), repo5, "nonexitent-manifest", randomImgData)
		So(err, ShouldBeNil)

		// Create metadb data for scannable image which errors during scan
		image71 := CreateImageWith().DefaultLayers().
			ImageConfig(ispec.Image{Created: DateRef(2000, 1, 1, 12, 0, 0, 0, time.UTC)}).Build()

		err = metaDB.SetRepoReference(context.Background(), repo7, "1.0.0", image71.AsImageMeta())
		So(err, ShouldBeNil)

		// Create image with vulnerabilities of all severities
		image81 := CreateImageWith().DefaultLayers().
			ImageConfig(ispec.Image{Created: DateRef(2020, 12, 1, 12, 0, 0, 0, time.UTC)}).Build()

		err = metaDB.SetRepoReference(context.Background(), repo8, "1.0.0", image81.AsImageMeta())
		So(err, ShouldBeNil)

		// create multiarch image with vulnerabilities
		multiarchImage := CreateRandomMultiarch()

		err = metaDB.SetRepoReference(context.Background(), repoMultiarch, multiarchImage.Images[0].DigestStr(),
			multiarchImage.Images[0].AsImageMeta())
		So(err, ShouldBeNil)

		err = metaDB.SetRepoReference(context.Background(), repoMultiarch, multiarchImage.Images[1].DigestStr(),
			multiarchImage.Images[1].AsImageMeta())
		So(err, ShouldBeNil)

		err = metaDB.SetRepoReference(context.Background(), repoMultiarch, multiarchImage.Images[2].DigestStr(),
			multiarchImage.Images[2].AsImageMeta())
		So(err, ShouldBeNil)

		err = metaDB.SetRepoReference(context.Background(), repoMultiarch, "tagIndex", multiarchImage.AsImageMeta())
		So(err, ShouldBeNil)

		err = metaDB.SetRepoMeta("repo-with-bad-tag-digest", mTypes.RepoMeta{
			Name: "repo-with-bad-tag-digest",
			Tags: map[mTypes.Tag]mTypes.Descriptor{
				"tag": {MediaType: ispec.MediaTypeImageManifest, Digest: godigest.FromString("1").String()},
			},
		})
		So(err, ShouldBeNil)
		// Keep a record of all the image references / digest pairings
		// This is normally done in MetaDB, but we want to verify
		// the whole flow, including MetaDB
		imageMap := map[string]string{}

		image11Digest := image11.ManifestDescriptor.Digest.String()
		image11Media := image11.ManifestDescriptor.MediaType
		image11Name := repo1 + ":0.1.0"
		imageMap[image11Name] = image11Digest
		image12Digest := image12.ManifestDescriptor.Digest.String()
		image12Media := image12.ManifestDescriptor.MediaType
		image12Name := repo1 + ":1.0.0"
		imageMap[image12Name] = image12Digest
		image13Digest := image13.ManifestDescriptor.Digest.String()
		image13Media := image13.ManifestDescriptor.MediaType
		image13Name := repo1 + ":1.1.0"
		imageMap[image13Name] = image13Digest
		image14Digest := image14.ManifestDescriptor.Digest.String()
		image14Media := image14.ManifestDescriptor.MediaType
		image14Name := repo1 + ":1.0.1"
		imageMap[image14Name] = image14Digest
		image21Digest := image21.ManifestDescriptor.Digest.String()
		image21Media := image21.ManifestDescriptor.MediaType
		image21Name := repo2 + ":1.0.0"
		imageMap[image21Name] = image21Digest
		image61Digest := image61.ManifestDescriptor.Digest.String()
		image61Media := image61.ManifestDescriptor.MediaType
		image61Name := repo6 + ":1.0.0"
		imageMap[image61Name] = image61Digest
		image71Digest := image71.ManifestDescriptor.Digest.String()
		image71Media := image71.ManifestDescriptor.MediaType
		image71Name := repo7 + ":1.0.0"
		imageMap[image71Name] = image71Digest
		image81Digest := image81.ManifestDescriptor.Digest.String()
		image81Media := image81.ManifestDescriptor.MediaType
		image81Name := repo8 + ":1.0.0"
		imageMap[image81Name] = image81Digest
		indexDigest := multiarchImage.IndexDescriptor.Digest.String()
		indexMedia := multiarchImage.IndexDescriptor.MediaType
		indexName := repoMultiarch + ":tagIndex"
		imageMap[indexName] = indexDigest
		indexM1Digest := multiarchImage.Images[0].ManifestDescriptor.Digest.String()
		indexM1Name := "repoIndex@" + indexM1Digest
		imageMap[indexM1Name] = indexM1Digest
		indexM2Digest := multiarchImage.Images[1].ManifestDescriptor.Digest.String()
		indexM2Name := "repoIndex@" + indexM2Digest
		imageMap[indexM2Name] = indexM2Digest
		indexM3Digest := multiarchImage.Images[2].ManifestDescriptor.Digest.String()
		indexM3Name := "repoIndex@" + indexM3Digest
		imageMap[indexM3Name] = indexM3Digest

		log := log.NewLogger("debug", "")

		// Initialize a test CVE cache
		cache := cvecache.NewCveCache(100, log)

		// MetaDB loaded with initial data, now mock the scanner
		// Setup test CVE data in mock scanner
		scanner := mocks.CveScannerMock{
			ScanImageFn: func(ctx context.Context, image string) (map[string]cvemodel.CVE, error) {
				result := cache.Get(image)
				// Will not match sending the repo:tag as a parameter, but we don't care
				if result != nil {
					return result, nil
				}

				repo, ref, isTag := zcommon.GetImageDirAndReference(image)
				if isTag {
					foundRef, ok := imageMap[image]
					if !ok {
						return nil, ErrBadTest
					}
					ref = foundRef
				}

				defer func() {
					t.Logf("ScanImageFn cached for image %s digest %s: %v", image, ref, cache.Get(ref))
				}()

				// Images in chronological order
				if repo == repo1 && ref == image11Digest {
					result := map[string]cvemodel.CVE{
						"CVE1": {
							ID:          "CVE1",
							Severity:    "MEDIUM",
							Title:       "Title CVE1",
							Description: "Description CVE1",
						},
					}

					cache.Add(ref, result)

					return result, nil
				}

				if repo == repo1 && zcommon.Contains([]string{image12Digest, image21Digest}, ref) {
					result := map[string]cvemodel.CVE{
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
					}

					cache.Add(ref, result)

					return result, nil
				}

				if repo == repo1 && ref == image13Digest {
					result := map[string]cvemodel.CVE{
						"CVE3": {
							ID:          "CVE3",
							Severity:    "LOW",
							Title:       "Title CVE3",
							Description: "Description CVE3",
						},
					}

					cache.Add(ref, result)

					return result, nil
				}

				// As a minor release on 1.0.0 banch
				// does not include all fixes published in 1.1.0
				if repo == repo1 && ref == image14Digest {
					result := map[string]cvemodel.CVE{
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
					}

					cache.Add(ref, result)

					return result, nil
				}

				// Unexpected error while scanning
				if repo == repo7 {
					return map[string]cvemodel.CVE{}, ErrFailedScan
				}

				if (repo == repoMultiarch && ref == indexDigest) ||
					(repo == repoMultiarch && ref == indexM1Digest) {
					result := map[string]cvemodel.CVE{
						"CVE1": {
							ID:          "CVE1",
							Severity:    "MEDIUM",
							Title:       "Title CVE1",
							Description: "Description CVE1",
						},
					}

					// Simulate scanning an index results in scanning its manifests
					if ref == indexDigest {
						cache.Add(indexM1Digest, result)
						cache.Add(indexM2Digest, map[string]cvemodel.CVE{})
						cache.Add(indexM3Digest, map[string]cvemodel.CVE{})
					}

					cache.Add(ref, result)

					return result, nil
				}

				if repo == repo8 && ref == image81Digest {
					result := map[string]cvemodel.CVE{
						"CVE0": {
							ID:          "CVE0",
							Severity:    "UNKNOWN",
							Title:       "Title CVE0",
							Description: "Description CVE0",
						},
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
						"CVE4": {
							ID:          "CVE4",
							Severity:    "CRITICAL",
							Title:       "Title CVE4",
							Description: "Description CVE4",
						},
						"CVE5": {
							ID:          "CVE5",
							Severity:    "CRITICAL",
							Title:       "Title CVE5",
							Description: "Description CVE5",
						},
						"CVE6": {
							ID:          "CVE6",
							Severity:    "LOW",
							Title:       "Title CVE6",
							Description: "Description CVE6",
						},
					}

					cache.Add(ref, result)

					return result, nil
				}

				// By default the image has no vulnerabilities
				result = map[string]cvemodel.CVE{}
				cache.Add(ref, result)

				return result, nil
			},
			IsImageFormatScannableFn: func(repo string, reference string) (bool, error) {
				if repo == repoMultiarch {
					return true, nil
				}

				// Almost same logic compared to actual Trivy specific implementation
				imageDir, inputTag := repo, reference

				repoMeta, err := metaDB.GetRepoMeta(context.Background(), imageDir)
				if err != nil {
					return false, err
				}

				manifestDigestStr := reference

				if zcommon.IsTag(reference) {
					var ok bool

					descriptor, ok := repoMeta.Tags[inputTag]
					if !ok {
						return false, zerr.ErrTagMetaNotFound
					}

					manifestDigestStr = descriptor.Digest
				}

				manifestDigest, err := godigest.Parse(manifestDigestStr)
				if err != nil {
					return false, err
				}

				manifestData, err := metaDB.GetImageMeta(manifestDigest)
				if err != nil {
					return false, err
				}

				for _, imageLayer := range manifestData.Manifests[0].Manifest.Layers {
					switch imageLayer.MediaType {
					case ispec.MediaTypeImageLayerGzip, ispec.MediaTypeImageLayer, string(regTypes.DockerLayer):

						return true, nil
					default:

						return false, zerr.ErrScanNotSupported
					}
				}

				return false, nil
			},
			IsImageMediaScannableFn: func(repo, digest, mediaType string) (bool, error) {
				if repo == repo2 && digest == image21Digest {
					return false, zerr.ErrScanNotSupported
				}
				if repo == repo100 {
					return false, zerr.ErrRepoMetaNotFound
				}

				return true, nil
			},
			IsResultCachedFn: func(digest string) bool {
				t.Logf("IsResultCachedFn found in cache for digest %s: %v", digest, cache.Get(digest))

				return cache.Contains(digest)
			},
			GetCachedResultFn: func(digest string) map[string]cvemodel.CVE {
				t.Logf("GetCachedResultFn found in cache for digest %s: %v", digest, cache.Get(digest))

				return cache.Get(digest)
			},
		}

		cveInfo := cveinfo.BaseCveInfo{Log: log, Scanner: scanner, MetaDB: metaDB}

		t.Log("\nTest GetCVEListForImage\n")

		pageInput := cvemodel.PageInput{
			SortBy: cveinfo.SeverityDsc,
		}

		ctx := context.Background()

		// Image is found
		cveList, cveSummary, pageInfo, err := cveInfo.GetCVEListForImage(ctx, repo1, "0.1.0", "", "", "", pageInput)
		So(err, ShouldBeNil)
		So(len(cveList), ShouldEqual, 1)
		So(cveList[0].ID, ShouldEqual, "CVE1")
		So(pageInfo.ItemCount, ShouldEqual, 1)
		So(pageInfo.TotalCount, ShouldEqual, 1)
		So(cveSummary.Count, ShouldEqual, 1)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 0)
		So(cveSummary.MediumCount, ShouldEqual, 1)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "MEDIUM")

		cveList, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, repo1, "1.0.0", "", "", "", pageInput)
		So(err, ShouldBeNil)
		So(len(cveList), ShouldEqual, 3)
		So(cveList[0].ID, ShouldEqual, "CVE2")
		So(cveList[1].ID, ShouldEqual, "CVE1")
		So(cveList[2].ID, ShouldEqual, "CVE3")
		So(pageInfo.ItemCount, ShouldEqual, 3)
		So(pageInfo.TotalCount, ShouldEqual, 3)
		So(cveSummary.Count, ShouldEqual, 3)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 1)
		So(cveSummary.MediumCount, ShouldEqual, 1)
		So(cveSummary.HighCount, ShouldEqual, 1)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "HIGH")

		cveList, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, repo1, "1.0.1", "", "", "", pageInput)
		So(err, ShouldBeNil)
		So(len(cveList), ShouldEqual, 2)
		So(cveList[0].ID, ShouldEqual, "CVE1")
		So(cveList[1].ID, ShouldEqual, "CVE3")
		So(pageInfo.ItemCount, ShouldEqual, 2)
		So(pageInfo.TotalCount, ShouldEqual, 2)
		So(cveSummary.Count, ShouldEqual, 2)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 1)
		So(cveSummary.MediumCount, ShouldEqual, 1)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "MEDIUM")

		cveList, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, repo1, "1.1.0", "", "", "", pageInput)
		So(err, ShouldBeNil)
		So(len(cveList), ShouldEqual, 1)
		So(cveList[0].ID, ShouldEqual, "CVE3")
		So(pageInfo.ItemCount, ShouldEqual, 1)
		So(pageInfo.TotalCount, ShouldEqual, 1)
		So(cveSummary.Count, ShouldEqual, 1)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 1)
		So(cveSummary.MediumCount, ShouldEqual, 0)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "LOW")

		cveList, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, repo6, "1.0.0", "", "", "", pageInput)
		So(err, ShouldBeNil)
		So(len(cveList), ShouldEqual, 0)
		So(pageInfo.ItemCount, ShouldEqual, 0)
		So(pageInfo.TotalCount, ShouldEqual, 0)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 0)
		So(cveSummary.MediumCount, ShouldEqual, 0)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "NONE")

		cveList, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, repo8, "1.0.0", "", "", "", pageInput)
		So(err, ShouldBeNil)
		So(len(cveList), ShouldEqual, 7)
		So(pageInfo.ItemCount, ShouldEqual, 7)
		So(pageInfo.TotalCount, ShouldEqual, 7)
		So(cveSummary.Count, ShouldEqual, 7)
		So(cveSummary.UnknownCount, ShouldEqual, 1)
		So(cveSummary.LowCount, ShouldEqual, 2)
		So(cveSummary.MediumCount, ShouldEqual, 1)
		So(cveSummary.HighCount, ShouldEqual, 1)
		So(cveSummary.CriticalCount, ShouldEqual, 2)
		So(cveSummary.MaxSeverity, ShouldEqual, "CRITICAL")

		_, _, _, err = cveInfo.GetCVEDiffListForImages(ctx, "repo8:1.0.0", "repo1@"+image13Digest, "", "", pageInput)
		So(err, ShouldBeNil)
		_, _, _, err = cveInfo.GetCVEDiffListForImages(ctx, "repo8:1.0.0", "repo1:0.1.0", "", "", pageInput)
		So(err, ShouldBeNil)

		// Image is multiarch
		cveList, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, repoMultiarch, "tagIndex", "", "", "", pageInput)
		So(err, ShouldBeNil)
		So(len(cveList), ShouldEqual, 1)
		So(cveList[0].ID, ShouldEqual, "CVE1")
		So(pageInfo.ItemCount, ShouldEqual, 1)
		So(pageInfo.TotalCount, ShouldEqual, 1)
		So(cveSummary.Count, ShouldEqual, 1)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 0)
		So(cveSummary.MediumCount, ShouldEqual, 1)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "MEDIUM")

		// Image is not scannable
		cveList, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, repo2, "1.0.0", "", "", "", pageInput)
		So(err, ShouldEqual, zerr.ErrScanNotSupported)
		So(len(cveList), ShouldEqual, 0)
		So(pageInfo.ItemCount, ShouldEqual, 0)
		So(pageInfo.TotalCount, ShouldEqual, 0)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 0)
		So(cveSummary.MediumCount, ShouldEqual, 0)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "")

		// Tag is not found
		cveList, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, repo3, "1.0.0", "", "", "", pageInput)
		So(err, ShouldEqual, zerr.ErrTagMetaNotFound)
		So(len(cveList), ShouldEqual, 0)
		So(pageInfo.ItemCount, ShouldEqual, 0)
		So(pageInfo.TotalCount, ShouldEqual, 0)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 0)
		So(cveSummary.MediumCount, ShouldEqual, 0)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "")

		// Scan failed
		cveList, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, repo7, "1.0.0", "", "", "", pageInput)
		So(err, ShouldEqual, ErrFailedScan)
		So(len(cveList), ShouldEqual, 0)
		So(pageInfo.ItemCount, ShouldEqual, 0)
		So(pageInfo.TotalCount, ShouldEqual, 0)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 0)
		So(cveSummary.MediumCount, ShouldEqual, 0)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "")

		// Tag is not found
		cveList, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, "repo-with-bad-tag-digest", "tag", "", "", "", pageInput)
		So(err, ShouldEqual, zerr.ErrImageMetaNotFound)
		So(len(cveList), ShouldEqual, 0)
		So(pageInfo.ItemCount, ShouldEqual, 0)
		So(pageInfo.TotalCount, ShouldEqual, 0)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 0)
		So(cveSummary.MediumCount, ShouldEqual, 0)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "")

		// Repo is not found
		cveList, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, repo100, "1.0.0", "", "", "", pageInput)
		So(err, ShouldEqual, zerr.ErrRepoMetaNotFound)
		So(len(cveList), ShouldEqual, 0)
		So(pageInfo.ItemCount, ShouldEqual, 0)
		So(pageInfo.TotalCount, ShouldEqual, 0)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 0)
		So(cveSummary.MediumCount, ShouldEqual, 0)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "")

		// By this point the cache should already be pupulated by previous function calls
		t.Log("\nTest GetCVESummaryForImage\n")

		// Image is found
		cveSummary, err = cveInfo.GetCVESummaryForImageMedia(ctx, repo1, image11Digest, image11Media)
		So(err, ShouldBeNil)
		So(cveSummary.Count, ShouldEqual, 1)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 0)
		So(cveSummary.MediumCount, ShouldEqual, 1)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "MEDIUM")

		cveSummary, err = cveInfo.GetCVESummaryForImageMedia(ctx, repo1, image12Digest, image12Media)
		So(err, ShouldBeNil)
		So(cveSummary.Count, ShouldEqual, 3)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 1)
		So(cveSummary.MediumCount, ShouldEqual, 1)
		So(cveSummary.HighCount, ShouldEqual, 1)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "HIGH")

		cveSummary, err = cveInfo.GetCVESummaryForImageMedia(ctx, repo1, image14Digest, image14Media)
		So(err, ShouldBeNil)
		So(cveSummary.Count, ShouldEqual, 2)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 1)
		So(cveSummary.MediumCount, ShouldEqual, 1)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "MEDIUM")

		cveSummary, err = cveInfo.GetCVESummaryForImageMedia(ctx, repo1, image13Digest, image13Media)
		So(err, ShouldBeNil)
		So(cveSummary.Count, ShouldEqual, 1)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 1)
		So(cveSummary.MediumCount, ShouldEqual, 0)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "LOW")

		cveSummary, err = cveInfo.GetCVESummaryForImageMedia(ctx, repo6, image61Digest, image61Media)
		So(err, ShouldBeNil)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 0)
		So(cveSummary.MediumCount, ShouldEqual, 0)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "NONE")

		cveSummary, err = cveInfo.GetCVESummaryForImageMedia(ctx, repo8, image81Digest, image81Media)
		So(err, ShouldBeNil)
		So(cveSummary.Count, ShouldEqual, 7)
		So(cveSummary.UnknownCount, ShouldEqual, 1)
		So(cveSummary.LowCount, ShouldEqual, 2)
		So(cveSummary.MediumCount, ShouldEqual, 1)
		So(cveSummary.HighCount, ShouldEqual, 1)
		So(cveSummary.CriticalCount, ShouldEqual, 2)
		So(cveSummary.MaxSeverity, ShouldEqual, "CRITICAL")

		// Image is multiarch
		cveSummary, err = cveInfo.GetCVESummaryForImageMedia(ctx, repoMultiarch, indexDigest, indexMedia)
		So(err, ShouldBeNil)
		So(cveSummary.Count, ShouldEqual, 1)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 0)
		So(cveSummary.MediumCount, ShouldEqual, 1)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "MEDIUM")

		// Image is not scannable
		cveSummary, err = cveInfo.GetCVESummaryForImageMedia(ctx, repo2, image21Digest, image21Media)
		So(err, ShouldEqual, zerr.ErrScanNotSupported)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 0)
		So(cveSummary.MediumCount, ShouldEqual, 0)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "")

		// Scan failed
		cveSummary, err = cveInfo.GetCVESummaryForImageMedia(ctx, repo5, image71Digest, image71Media)
		So(err, ShouldBeNil)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 0)
		So(cveSummary.MediumCount, ShouldEqual, 0)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "")

		// Repo is not found
		cveSummary, err = cveInfo.GetCVESummaryForImageMedia(ctx, repo100,
			godigest.FromString("missing_digest").String(), ispec.MediaTypeImageManifest)
		So(err, ShouldEqual, zerr.ErrRepoMetaNotFound)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 0)
		So(cveSummary.MediumCount, ShouldEqual, 0)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "")

		t.Log("\nTest GetImageListWithCVEFixed\n")

		// Image is found
		tagList, err := cveInfo.GetImageListWithCVEFixed(ctx, repo1, "CVE1")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 1)
		So(tagList[0].Tag, ShouldEqual, "1.1.0")

		tagList, err = cveInfo.GetImageListWithCVEFixed(ctx, repo1, "CVE2")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 2)
		expectedTags := []string{"1.0.1", "1.1.0"}
		So(expectedTags, ShouldContain, tagList[0].Tag)
		So(expectedTags, ShouldContain, tagList[1].Tag)

		tagList, err = cveInfo.GetImageListWithCVEFixed(ctx, repo1, "CVE3")
		So(err, ShouldBeNil)
		// CVE3 is not present in 0.1.0, but that is older than all other
		// images where it is present. The rest of the images explicitly  have it.
		// This means we consider it not fixed in any image.
		So(len(tagList), ShouldEqual, 0)

		// Image doesn't have any CVEs in the first place
		tagList, err = cveInfo.GetImageListWithCVEFixed(ctx, repo6, "CVE1")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 1)
		So(tagList[0].Tag, ShouldEqual, "1.0.0")

		// Image is not scannable
		tagList, err = cveInfo.GetImageListWithCVEFixed(ctx, repo2, "CVE100")
		// CVE is not considered fixed as scan is not possible
		// but do not return an error
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 0)

		// Repo is not found, there could potentially be unaffected tags in the repo
		// but we can't access their data
		tagList, err = cveInfo.GetImageListWithCVEFixed(ctx, repo100, "CVE100")
		So(err, ShouldEqual, zerr.ErrRepoMetaNotFound)
		So(len(tagList), ShouldEqual, 0)

		t.Log("\nTest GetImageListForCVE\n")

		// Image is found
		tagList, err = cveInfo.GetImageListForCVE(ctx, repo1, "CVE1")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 3)
		expectedTags = []string{"0.1.0", "1.0.0", "1.0.1"}
		So(expectedTags, ShouldContain, tagList[0].Tag)
		So(expectedTags, ShouldContain, tagList[1].Tag)
		So(expectedTags, ShouldContain, tagList[2].Tag)

		tagList, err = cveInfo.GetImageListForCVE(ctx, repo1, "CVE2")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 1)
		So(tagList[0].Tag, ShouldEqual, "1.0.0")

		tagList, err = cveInfo.GetImageListForCVE(ctx, repo1, "CVE3")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 3)
		expectedTags = []string{"1.0.0", "1.0.1", "1.1.0"}
		So(expectedTags, ShouldContain, tagList[0].Tag)
		So(expectedTags, ShouldContain, tagList[1].Tag)
		So(expectedTags, ShouldContain, tagList[2].Tag)

		// Image/repo doesn't have the CVE at all
		tagList, err = cveInfo.GetImageListForCVE(ctx, repo6, "CVE1")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 0)

		// Image is not scannable
		tagList, err = cveInfo.GetImageListForCVE(ctx, repo2, "CVE100")
		// Image is not considered affected with CVE as scan is not possible
		// but do not return an error
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 0)

		// Tag is not found, but we should not error
		tagList, err = cveInfo.GetImageListForCVE(ctx, repo3, "CVE101")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 0)

		// Repo is not found, assume it is affected by the CVE
		// But we don't have enough of its data to actually return it
		tagList, err = cveInfo.GetImageListForCVE(ctx, repo100, "CVE100")
		So(err, ShouldEqual, zerr.ErrRepoMetaNotFound)
		So(len(tagList), ShouldEqual, 0)

		t.Log("\nTest errors while scanning\n")

		faultyScanner := mocks.CveScannerMock{
			ScanImageFn: func(ctx context.Context, image string) (map[string]cvemodel.CVE, error) {
				// Could be any type of error, let's reuse this one
				return nil, zerr.ErrScanNotSupported
			},
		}

		cveInfo = cveinfo.BaseCveInfo{Log: log, Scanner: faultyScanner, MetaDB: metaDB}

		cveSummary, err = cveInfo.GetCVESummaryForImageMedia(ctx, repo1, image11Digest, image11Media)
		So(err, ShouldBeNil)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 0)
		So(cveSummary.MediumCount, ShouldEqual, 0)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "")

		cveList, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, repo1, "0.1.0", "", "", "", pageInput)
		So(err, ShouldNotBeNil)
		So(cveList, ShouldBeEmpty)
		So(pageInfo.ItemCount, ShouldEqual, 0)
		So(pageInfo.TotalCount, ShouldEqual, 0)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.UnknownCount, ShouldEqual, 0)
		So(cveSummary.LowCount, ShouldEqual, 0)
		So(cveSummary.MediumCount, ShouldEqual, 0)
		So(cveSummary.HighCount, ShouldEqual, 0)
		So(cveSummary.CriticalCount, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "")

		tagList, err = cveInfo.GetImageListWithCVEFixed(ctx, repo1, "CVE1")
		// CVE is not considered fixed as scan is not possible
		// but do not return an error
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 0)

		tagList, err = cveInfo.GetImageListForCVE(ctx, repo1, "CVE1")
		// Image is not considered affected with CVE as scan is not possible
		// but do not return an error
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 0)

		cveInfo = cveinfo.BaseCveInfo{Log: log, Scanner: mocks.CveScannerMock{
			IsImageFormatScannableFn: func(repo, reference string) (bool, error) {
				return false, nil
			},
		}, MetaDB: metaDB}

		_, err = cveInfo.GetImageListForCVE(ctx, repoMultiarch, "CVE1")
		So(err, ShouldBeNil)

		cveInfo = cveinfo.BaseCveInfo{Log: log, Scanner: mocks.CveScannerMock{
			IsImageFormatScannableFn: func(repo, reference string) (bool, error) {
				return true, nil
			},
			ScanImageFn: func(ctx context.Context, image string) (map[string]cvemodel.CVE, error) {
				return nil, zerr.ErrTypeAssertionFailed
			},
		}, MetaDB: metaDB}

		_, err = cveInfo.GetImageListForCVE(ctx, repoMultiarch, "CVE1")
		So(err, ShouldBeNil)

		cveInfo = cveinfo.BaseCveInfo{Log: log, Scanner: mocks.CveScannerMock{
			IsImageFormatScannableFn: func(repo, reference string) (bool, error) {
				return true, nil
			},
			ScanImageFn: func(ctx context.Context, image string) (map[string]cvemodel.CVE, error) {
				return nil, zerr.ErrTypeAssertionFailed
			},
		}, MetaDB: metaDB}
		_, _, _, err = cveInfo.GetCVEDiffListForImages(ctx, "repo8:1.0.0", "repo1:0.1.0", "", "", pageInput)
		So(err, ShouldNotBeNil)

		try := 0
		cveInfo = cveinfo.BaseCveInfo{Log: log, Scanner: mocks.CveScannerMock{
			IsImageFormatScannableFn: func(repo, reference string) (bool, error) {
				return true, nil
			},
			ScanImageFn: func(ctx context.Context, image string) (map[string]cvemodel.CVE, error) {
				if try == 1 {
					return nil, zerr.ErrTypeAssertionFailed
				}

				try++

				return make(map[string]cvemodel.CVE), nil
			},
		}, MetaDB: metaDB}
		_, _, _, err = cveInfo.GetCVEDiffListForImages(ctx, "repo8:1.0.0", "repo6:0.1.0", "", "", pageInput)
		So(err, ShouldNotBeNil)
	})
}

func getTags() ([]cvemodel.TagInfo, []cvemodel.TagInfo) {
	tags := make([]cvemodel.TagInfo, 0)

	firstTag := cvemodel.TagInfo{
		Tag: "1.0.0",
		Descriptor: cvemodel.Descriptor{
			Digest:    "sha256:eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb",
			MediaType: ispec.MediaTypeImageManifest,
		},
		Timestamp: time.Now(),
	}
	secondTag := cvemodel.TagInfo{
		Tag: "1.0.1",
		Descriptor: cvemodel.Descriptor{
			Digest:    "sha256:eca04f027f414362596f2632746d8a179362170b9ac9af772011fedcc3877ebb",
			MediaType: ispec.MediaTypeImageManifest,
		},
		Timestamp: time.Now(),
	}
	thirdTag := cvemodel.TagInfo{
		Tag: "1.0.2",
		Descriptor: cvemodel.Descriptor{
			Digest:    "sha256:eca04f027f414362596f2632746d8a170362170b9ac9af772011fedcc3877ebb",
			MediaType: ispec.MediaTypeImageManifest,
		},
		Timestamp: time.Now(),
	}
	fourthTag := cvemodel.TagInfo{
		Tag: "1.0.3",
		Descriptor: cvemodel.Descriptor{
			Digest:    "sha256:eca04f027f414362596f2632746d8a171362170b9ac9af772011fedcc3877ebb",
			MediaType: ispec.MediaTypeImageManifest,
		},
		Timestamp: time.Now(),
	}

	tags = append(tags, firstTag, secondTag, thirdTag, fourthTag)

	vulnerableTags := make([]cvemodel.TagInfo, 0)
	vulnerableTags = append(vulnerableTags, secondTag)

	return tags, vulnerableTags
}

func TestFixedTags(t *testing.T) {
	Convey("Test fixed tags", t, func() {
		allTags, vulnerableTags := getTags()

		fixedTags := cveinfo.GetFixedTags(allTags, vulnerableTags)
		So(len(fixedTags), ShouldEqual, 2)

		fixedTags = cveinfo.GetFixedTags(allTags, append(vulnerableTags, cvemodel.TagInfo{
			Tag: "taginfo",
			Descriptor: cvemodel.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    "sha256:eca04f027f414362596f2632746d8a179362170b9ac9af772011fedcc3877ebb",
			},
			Timestamp: time.Date(2000, time.July, 20, 10, 10, 10, 10, time.UTC),
		}))
		So(len(fixedTags), ShouldEqual, 3)
	})
}

func TestFixedTagsWithIndex(t *testing.T) {
	Convey("Test fixed tags", t, func() {
		tempDir := t.TempDir()
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		defaultVal := true
		conf.Storage.RootDirectory = tempDir
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{
				BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
				CVE: &extconf.CVEConfig{
					UpdateInterval: 24 * time.Hour,
					Trivy: &extconf.TrivyConfig{
						DBRepository: "ghcr.io/project-zot/trivy-db",
					},
				},
			},
		}

		logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
		So(err, ShouldBeNil)

		logPath := logFile.Name()
		defer os.Remove(logPath)

		writers := io.MultiWriter(os.Stdout, logFile)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()
		// push index with 2 manifests: one with vulns and one without
		vulnManifestCreated := time.Date(2010, 1, 1, 1, 1, 1, 1, time.UTC)
		vulnImageConfig := GetDefaultConfig()
		vulnImageConfig.Created = &vulnManifestCreated
		vulnImageConfig.Platform = ispec.Platform{OS: "linux", Architecture: "amd64"}
		vulnSingleArchImage := CreateImageWith().VulnerableLayers().VulnerableConfig(vulnImageConfig).Build()

		fixedManifestCreated := time.Date(2010, 1, 1, 1, 1, 1, 1, time.UTC)
		fixedImageConfig := GetDefaultConfig()
		fixedImageConfig.Created = &fixedManifestCreated
		fixedImageConfig.Platform = ispec.Platform{OS: "windows", Architecture: "amd64"}
		fixedSingleArchImage := CreateImageWith().DefaultLayers().ImageConfig(fixedImageConfig).Build()

		multiArchImage := CreateMultiarchWith().Images([]Image{vulnSingleArchImage, fixedSingleArchImage}).Build()

		err = UploadMultiarchImage(multiArchImage, baseURL, "repo", "multi-arch-tag")
		So(err, ShouldBeNil)

		// oldest vulnerability
		simpleVulnCreated := time.Date(2005, 1, 1, 1, 1, 1, 1, time.UTC)
		singleVulnImageConfig := GetDefaultConfig()
		singleVulnImageConfig.Created = &simpleVulnCreated
		singleVulnImageConfig.Platform = ispec.Platform{OS: "windows", Architecture: "amd64"}
		simpleVulnImage := CreateImageWith().VulnerableLayers().VulnerableConfig(singleVulnImageConfig).Build()

		err = UploadImage(simpleVulnImage, baseURL, "repo", "vuln-img")
		So(err, ShouldBeNil)

		// Wait for trivy db to download
		found, err := test.ReadLogFileAndSearchString(logPath, "cve-db update completed, next update scheduled after interval", 180*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		cveInfo := cveinfo.NewCVEInfo(ctlr.CveScanner, ctlr.MetaDB, ctlr.Log)

		tagsInfo, err := cveInfo.GetImageListWithCVEFixed(context.Background(), "repo", Vulnerability1ID)
		So(err, ShouldBeNil)
		So(len(tagsInfo), ShouldEqual, 1)
		So(len(tagsInfo[0].Manifests), ShouldEqual, 1)
		So(tagsInfo[0].Manifests[0].Digest, ShouldResemble, fixedSingleArchImage.ManifestDescriptor.Digest)

		const query = `
		{
			ImageListWithCVEFixed(id:"%s",image:"%s"){
				Results{
					RepoName
					Manifests {Digest}
				}
			}
		}`

		resp, _ := resty.R().Get(baseURL + constants.FullSearchPrefix + "?query=" +
			url.QueryEscape(fmt.Sprintf(query, Vulnerability1ID, "repo")))
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct := &zcommon.ImageListWithCVEFixedResponse{}
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Results), ShouldEqual, 1)
		So(len(responseStruct.Results[0].Manifests), ShouldEqual, 1)
		fixedManifestResp := responseStruct.Results[0].Manifests[0]
		So(fixedManifestResp.Digest, ShouldResemble, fixedSingleArchImage.ManifestDescriptor.Digest.String())
	})
}

func TestGetCVESummaryForImageMediaErrors(t *testing.T) {
	Convey("Errors", t, func() {
		storeController := storage.StoreController{}
		storeController.DefaultStore = mocks.MockedImageStore{}

		metaDB := mocks.MetaDBMock{}
		log := log.NewLogger("debug", "")

		Convey("IsImageMediaScannable returns false", func() {
			scanner := mocks.CveScannerMock{
				IsImageMediaScannableFn: func(repo, digest, mediaType string) (bool, error) {
					return false, zerr.ErrScanNotSupported
				},
			}

			cveInfo := cveinfo.NewCVEInfo(scanner, metaDB, log)

			_, err := cveInfo.GetCVESummaryForImageMedia(context.Background(), "repo", "digest", ispec.MediaTypeImageManifest)
			So(err, ShouldNotBeNil)
		})
	})
}
