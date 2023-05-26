//go:build search
// +build search

//nolint:lll,gosimple
package cveinfo_test

import (
	"encoding/json"
	"fmt"
	"io"
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

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/bolt"
	"zotregistry.io/zot/pkg/meta/repodb"
	boltdb_wrapper "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	"zotregistry.io/zot/pkg/storage"
	storageConstants "zotregistry.io/zot/pkg/storage/constants"
	"zotregistry.io/zot/pkg/storage/local"
	. "zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
)

const (
	username   = "test"
	passphrase = "test"
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

	err = CopyFiles("../../../../test/data", dir)
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
		defaultStore := local.NewImageStore(imgDir, false, storageConstants.DefaultGCDelay,
			false, false, log, metrics, nil, nil)
		storeController := storage.StoreController{DefaultStore: defaultStore}

		params := bolt.DBParameters{
			RootDir: dbDir,
		}
		boltDriver, err := bolt.GetBoltDriver(params)
		So(err, ShouldBeNil)

		repoDB, err := boltdb_wrapper.NewBoltDBWrapper(boltDriver, log)
		So(err, ShouldBeNil)

		err = repodb.ParseStorage(repoDB, storeController, log)
		So(err, ShouldBeNil)

		cveInfo := cveinfo.NewCVEInfo(storeController, repoDB, "", log)

		isValidImage, err := cveInfo.Scanner.IsImageFormatScannable("zot-test", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-test", "0.0.1")
		So(err, ShouldBeNil)
		So(isValidImage, ShouldEqual, true)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-test", "0.0.")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-noindex-test", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot--tet", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-noindex-test", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-squashfs-noblobs", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-squashfs-invalid-index", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-squashfs-invalid-blob", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-squashfs-test:0.3.22-squashfs", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = cveInfo.Scanner.IsImageFormatScannable("zot-nonreadable-test", "")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)
	})

	Convey("isIndexScanable", t, func() {
		log := log.NewLogger("debug", "")

		repoDB := &mocks.RepoDBMock{
			GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
				return repodb.RepoMetadata{
					Tags: map[string]repodb.Descriptor{
						"tag": {MediaType: ispec.MediaTypeImageIndex},
					},
				}, nil
			},
		}
		storeController := storage.StoreController{
			DefaultStore: mocks.MockedImageStore{},
		}

		cveInfo := cveinfo.NewCVEInfo(storeController, repoDB, "", log)

		isScanable, err := cveInfo.Scanner.IsImageFormatScannable("repo", "tag")
		So(err, ShouldBeNil)
		So(isScanable, ShouldBeFalse)
	})
}

func TestCVESearchDisabled(t *testing.T) {
	Convey("Test with CVE search disabled", t, func() {
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
		ctlr.Log.Logger = ctlr.Log.Output(writers)
		ctrlManager := NewControllerManager(ctlr)

		ctrlManager.StartAndWait(port)

		// Wait for trivy db to download
		found, err := ReadLogFileAndSearchString(logPath, "CVE config not provided, skipping CVE update", 90*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		defer ctrlManager.StopServer()

		resp, _ := resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(string(resp.Body()), ShouldContainSubstring, "search: CVE search is disabled")
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListForCVE(id:\"CVE-201-20482\"){Results{RepoName%20Tag}}}")
		So(string(resp.Body()), ShouldContainSubstring, "search: CVE search is disabled")
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + "randomId" + "\",image:\"zot-test\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(string(resp.Body()), ShouldContainSubstring, "search: CVE search is disabled")
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestCVESearch(t *testing.T) {
	Convey("Test image vulnerability scanning", t, func() {
		updateDuration, _ := time.ParseDuration("1h")
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := MakeHtpasswdFile()
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
		ctrlManager := NewControllerManager(ctlr)

		ctrlManager.StartAndWait(port)

		// trivy db download fail
		err = os.Mkdir(dbDir+"/_trivy", 0o000)
		So(err, ShouldBeNil)
		found, err := ReadLogFileAndSearchString(logPath, "Error downloading Trivy DB to destination dir", 180*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		err = os.Chmod(dbDir+"/_trivy", 0o755)
		So(err, ShouldBeNil)

		// Wait for trivy db to download
		found, err = ReadLogFileAndSearchString(logPath, "DB update completed, next update scheduled", 180*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		defer ctrlManager.StopServer()

		// without creds, should get access error
		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
		var apiErr api.Error
		err = json.Unmarshal(resp.Body(), &apiErr)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + constants.FullSearchPrefix)
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

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		var cveResult CveResult
		contains := false
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		err = json.Unmarshal(resp.Body(), &cveResult)
		So(err, ShouldBeNil)
		for _, err := range cveResult.Errors {
			result := strings.Contains(err.Message, "no reference provided")
			if result {
				contains = result
			}
		}
		So(contains, ShouldBeTrue)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &cveResult)
		So(err, ShouldBeNil)
		So(len(cveResult.ImgList.CVEResultForImage.CVEList), ShouldNotBeZeroValue)

		cvid := cveResult.ImgList.CVEResultForImage.CVEList[0].ID

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cvid + "\",image:\"zot-test\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var imgListWithCVEFixed ImgListWithCVEFixed
		err = json.Unmarshal(resp.Body(), &imgListWithCVEFixed)
		So(err, ShouldBeNil)
		So(len(imgListWithCVEFixed.Images), ShouldEqual, 0)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cvid + "\",image:\"zot-cve-test\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &imgListWithCVEFixed)
		So(err, ShouldBeNil)
		So(len(imgListWithCVEFixed.Images), ShouldEqual, 0)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cvid + "\",image:\"zot-test\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"b/zot-squashfs-test:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var cveSquashFSResult CveResult
		err = json.Unmarshal(resp.Body(), &cveSquashFSResult)
		So(err, ShouldBeNil)
		So(len(cveSquashFSResult.ImgList.CVEResultForImage.CVEList), ShouldBeZeroValue)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-squashfs-noindex:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cvid + "\",image:\"zot-squashfs-noindex\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-squashfs-invalid-index:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cvid + "\",image:\"zot-squashfs-invalid-index\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-squashfs-noblobs:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cvid + "\",image:\"zot-squashfs-noblob\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cvid + "\",image:\"zot-squashfs-test\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-squashfs-invalid-blob:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListWithCVEFixed(id:\"" + cvid + "\",image:\"zot-squashfs-invalid-blob\"){Results{RepoName%20LastUpdated}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-squashfs-test\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"cntos\"){Tag%20CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListForCVE(id:\"CVE-201-20482\"){Results{RepoName%20Tag}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test\"){Tag%20CVEList{Id%20Description}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){Tag}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Id%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Id%20Description}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Id}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){CVEList{Description}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// Testing Invalid Search URL
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(image:\"zot-test:0.0.1\"){Ta%20CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListForCVE(tet:\"CVE-2018-20482\"){Results{RepoName%20Tag}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={ImageistForCVE(id:\"CVE-2018-20482\"){Results{RepoName%20Tag}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListForCVE(id:\"CVE-2018-20482\"){ame%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={CVEListForImage(reo:\"zot-test:1.0.0\"){Tag%20CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + constants.FullSearchPrefix + "?query={ImageListForCVE(id:\"" + cvid + "\"){Results{RepoName%20Tag}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestCVEStruct(t *testing.T) {
	Convey("Unit test the CVE struct", t, func() {
		params := bolt.DBParameters{
			RootDir: t.TempDir(),
		}
		boltDriver, err := bolt.GetBoltDriver(params)
		So(err, ShouldBeNil)

		repoDB, err := boltdb_wrapper.NewBoltDBWrapper(boltDriver, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		// Create repodb data for scannable image with vulnerabilities
		timeStamp11 := time.Date(2008, 1, 1, 12, 0, 0, 0, time.UTC)

		configBlob11, err := json.Marshal(ispec.Image{
			Created: &timeStamp11,
		})
		So(err, ShouldBeNil)

		manifestBlob11, err := json.Marshal(ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Size:      0,
				Digest:    godigest.FromBytes(configBlob11),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayerGzip,
					Size:      0,
					Digest:    godigest.NewDigestFromEncoded(godigest.SHA256, "digest"),
				},
			},
		})
		So(err, ShouldBeNil)

		repoMeta11 := repodb.ManifestMetadata{
			ManifestBlob:  manifestBlob11,
			ConfigBlob:    configBlob11,
			DownloadCount: 0,
			Signatures:    repodb.ManifestSignatures{},
		}

		digest11 := godigest.FromBytes(manifestBlob11)
		err = repoDB.SetManifestMeta("repo1", digest11, repoMeta11)
		So(err, ShouldBeNil)
		err = repoDB.SetRepoReference("repo1", "0.1.0", digest11, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)

		timeStamp12 := time.Date(2009, 1, 1, 12, 0, 0, 0, time.UTC)

		configBlob12, err := json.Marshal(ispec.Image{
			Created: &timeStamp12,
		})
		So(err, ShouldBeNil)

		manifestBlob12, err := json.Marshal(ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Size:      0,
				Digest:    godigest.FromBytes(configBlob12),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayerGzip,
					Size:      0,
					Digest:    godigest.NewDigestFromEncoded(godigest.SHA256, "digest"),
				},
			},
		})
		So(err, ShouldBeNil)

		repoMeta12 := repodb.ManifestMetadata{
			ManifestBlob:  manifestBlob12,
			ConfigBlob:    configBlob12,
			DownloadCount: 0,
			Signatures:    repodb.ManifestSignatures{},
		}

		digest12 := godigest.FromBytes(manifestBlob12)
		err = repoDB.SetManifestMeta("repo1", digest12, repoMeta12)
		So(err, ShouldBeNil)
		err = repoDB.SetRepoReference("repo1", "1.0.0", digest12, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)

		timeStamp13 := time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC)

		configBlob13, err := json.Marshal(ispec.Image{
			Created: &timeStamp13,
		})
		So(err, ShouldBeNil)

		manifestBlob13, err := json.Marshal(ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Size:      0,
				Digest:    godigest.FromBytes(configBlob13),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayerGzip,
					Size:      0,
					Digest:    godigest.NewDigestFromEncoded(godigest.SHA256, "digest"),
				},
			},
		})
		So(err, ShouldBeNil)

		repoMeta13 := repodb.ManifestMetadata{
			ManifestBlob: manifestBlob13,
			ConfigBlob:   configBlob13,
		}

		digest13 := godigest.FromBytes(manifestBlob13)
		err = repoDB.SetManifestMeta("repo1", digest13, repoMeta13)
		So(err, ShouldBeNil)
		err = repoDB.SetRepoReference("repo1", "1.1.0", digest13, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)

		timeStamp14 := time.Date(2011, 1, 1, 12, 0, 0, 0, time.UTC)

		configBlob14, err := json.Marshal(ispec.Image{
			Created: &timeStamp14,
		})
		So(err, ShouldBeNil)

		manifestBlob14, err := json.Marshal(ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Size:      0,
				Digest:    godigest.FromBytes(configBlob14),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayerGzip,
					Size:      0,
					Digest:    godigest.NewDigestFromEncoded(godigest.SHA256, "digest"),
				},
			},
		})
		So(err, ShouldBeNil)

		repoMeta14 := repodb.ManifestMetadata{
			ManifestBlob: manifestBlob14,
			ConfigBlob:   configBlob14,
		}

		digest14 := godigest.FromBytes(manifestBlob14)
		err = repoDB.SetManifestMeta("repo1", digest14, repoMeta14)
		So(err, ShouldBeNil)
		err = repoDB.SetRepoReference("repo1", "1.0.1", digest14, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)

		// Create repodb data for scannable image with no vulnerabilities
		timeStamp61 := time.Date(2011, 1, 1, 12, 0, 0, 0, time.UTC)

		configBlob61, err := json.Marshal(ispec.Image{
			Created: &timeStamp61,
		})
		So(err, ShouldBeNil)

		manifestBlob61, err := json.Marshal(ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Size:      0,
				Digest:    godigest.FromBytes(configBlob61),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayerGzip,
					Size:      0,
					Digest:    godigest.NewDigestFromEncoded(godigest.SHA256, "digest"),
				},
			},
		})
		So(err, ShouldBeNil)

		repoMeta61 := repodb.ManifestMetadata{
			ManifestBlob: manifestBlob61,
			ConfigBlob:   configBlob61,
		}

		digest61 := godigest.FromBytes(manifestBlob61)
		err = repoDB.SetManifestMeta("repo6", digest61, repoMeta61)
		So(err, ShouldBeNil)
		err = repoDB.SetRepoReference("repo6", "1.0.0", digest61, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)

		// Create repodb data for image not supporting scanning
		timeStamp21 := time.Date(2009, 1, 1, 12, 0, 0, 0, time.UTC)

		configBlob21, err := json.Marshal(ispec.Image{
			Created: &timeStamp21,
		})
		So(err, ShouldBeNil)

		manifestBlob21, err := json.Marshal(ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Size:      0,
				Digest:    godigest.FromBytes(configBlob21),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayerNonDistributableGzip, //nolint:staticcheck
					Size:      0,
					Digest:    godigest.NewDigestFromEncoded(godigest.SHA256, "digest"),
				},
			},
		})
		So(err, ShouldBeNil)

		repoMeta21 := repodb.ManifestMetadata{
			ManifestBlob: manifestBlob21,
			ConfigBlob:   configBlob21,
		}

		digest21 := godigest.FromBytes(manifestBlob21)
		err = repoDB.SetManifestMeta("repo2", digest21, repoMeta21)
		So(err, ShouldBeNil)
		err = repoDB.SetRepoReference("repo2", "1.0.0", digest21, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)

		// Create repodb data for invalid images/negative tests
		manifestBlob31 := []byte("invalid manifest blob")
		So(err, ShouldBeNil)

		repoMeta31 := repodb.ManifestMetadata{
			ManifestBlob: manifestBlob31,
		}

		digest31 := godigest.FromBytes(manifestBlob31)
		err = repoDB.SetManifestMeta("repo3", digest31, repoMeta31)
		So(err, ShouldBeNil)
		err = repoDB.SetRepoReference("repo3", "invalid-manifest", digest31, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)

		configBlob41 := []byte("invalid config blob")
		So(err, ShouldBeNil)

		repoMeta41 := repodb.ManifestMetadata{
			ConfigBlob: configBlob41,
		}

		digest41 := godigest.FromString("abc7")
		err = repoDB.SetManifestMeta("repo4", digest41, repoMeta41)
		So(err, ShouldBeNil)
		err = repoDB.SetRepoReference("repo4", "invalid-config", digest41, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)

		digest51 := godigest.FromString("abc8")
		err = repoDB.SetRepoReference("repo5", "nonexitent-manifest", digest51, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)

		// ------ Multiarch image
		_, _, manifestContent1, err := GetRandomImageComponents(100)
		So(err, ShouldBeNil)
		manifestContent1Blob, err := json.Marshal(manifestContent1)
		So(err, ShouldBeNil)
		diestManifestFromIndex1 := godigest.FromBytes(manifestContent1Blob)
		err = repoDB.SetManifestData(diestManifestFromIndex1, repodb.ManifestData{
			ManifestBlob: manifestContent1Blob,
			ConfigBlob:   []byte("{}"),
		})
		So(err, ShouldBeNil)

		_, _, manifestContent2, err := GetRandomImageComponents(100)
		So(err, ShouldBeNil)
		manifestContent2Blob, err := json.Marshal(manifestContent2)
		So(err, ShouldBeNil)
		diestManifestFromIndex2 := godigest.FromBytes(manifestContent2Blob)
		err = repoDB.SetManifestData(diestManifestFromIndex1, repodb.ManifestData{
			ManifestBlob: manifestContent2Blob,
			ConfigBlob:   []byte("{}"),
		})
		So(err, ShouldBeNil)

		indexBlob, err := GetIndexBlobWithManifests(
			[]godigest.Digest{diestManifestFromIndex1, diestManifestFromIndex2},
		)
		So(err, ShouldBeNil)

		indexDigest := godigest.FromBytes(indexBlob)
		err = repoDB.SetIndexData(indexDigest, repodb.IndexData{
			IndexBlob: indexBlob,
		})
		So(err, ShouldBeNil)

		err = repoDB.SetRepoReference("repoIndex", "tagIndex", indexDigest, ispec.MediaTypeImageIndex)
		So(err, ShouldBeNil)

		// RepoDB loaded with initial data, mock the scanner
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

				if image == "repoIndex:tagIndex" {
					return map[string]cvemodel.CVE{
						"CVE1": {
							ID:          "CVE1",
							Severity:    "MEDIUM",
							Title:       "Title CVE1",
							Description: "Description CVE1",
						},
					}, nil
				}

				// By default the image has no vulnerabilities
				return map[string]cvemodel.CVE{}, nil
			},
			CompareSeveritiesFn: func(severity1, severity2 string) int {
				return severities[severity2] - severities[severity1]
			},
			IsImageFormatScannableFn: func(repo string, reference string) (bool, error) {
				if repo == "repoIndex" {
					return true, nil
				}

				// Almost same logic compared to actual Trivy specific implementation
				imageDir, inputTag := repo, reference

				repoMeta, err := repoDB.GetRepoMeta(imageDir)
				if err != nil {
					return false, err
				}

				manifestDigestStr, ok := repoMeta.Tags[inputTag]
				if !ok {
					return false, zerr.ErrTagMetaNotFound
				}

				manifestDigest, err := godigest.Parse(manifestDigestStr.Digest)
				if err != nil {
					return false, err
				}

				manifestData, err := repoDB.GetManifestData(manifestDigest)
				if err != nil {
					return false, err
				}

				var manifestContent ispec.Manifest

				err = json.Unmarshal(manifestData.ManifestBlob, &manifestContent)
				if err != nil {
					return false, zerr.ErrScanNotSupported
				}

				for _, imageLayer := range manifestContent.Layers {
					switch imageLayer.MediaType {
					case ispec.MediaTypeImageLayerGzip, ispec.MediaTypeImageLayer, string(regTypes.DockerLayer):

						return true, nil
					default:

						return false, zerr.ErrScanNotSupported
					}
				}

				return false, nil
			},
		}

		log := log.NewLogger("debug", "")
		cveInfo := cveinfo.BaseCveInfo{Log: log, Scanner: scanner, RepoDB: repoDB}

		t.Log("Test GetCVESummaryForImage")

		// Image is found
		cveSummary, err := cveInfo.GetCVESummaryForImage("repo1", "0.1.0")
		So(err, ShouldBeNil)
		So(cveSummary.Count, ShouldEqual, 1)
		So(cveSummary.MaxSeverity, ShouldEqual, "MEDIUM")

		cveSummary, err = cveInfo.GetCVESummaryForImage("repo1", "1.0.0")
		So(err, ShouldBeNil)
		So(cveSummary.Count, ShouldEqual, 3)
		So(cveSummary.MaxSeverity, ShouldEqual, "HIGH")

		cveSummary, err = cveInfo.GetCVESummaryForImage("repo1", "1.0.1")
		So(err, ShouldBeNil)
		So(cveSummary.Count, ShouldEqual, 2)
		So(cveSummary.MaxSeverity, ShouldEqual, "MEDIUM")

		cveSummary, err = cveInfo.GetCVESummaryForImage("repo1", "1.1.0")
		So(err, ShouldBeNil)
		So(cveSummary.Count, ShouldEqual, 1)
		So(cveSummary.MaxSeverity, ShouldEqual, "LOW")

		cveSummary, err = cveInfo.GetCVESummaryForImage("repo6", "1.0.0")
		So(err, ShouldBeNil)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "NONE")

		// Image is not scannable
		cveSummary, err = cveInfo.GetCVESummaryForImage("repo2", "1.0.0")
		So(err, ShouldEqual, zerr.ErrScanNotSupported)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "")

		// Tag is not found
		cveSummary, err = cveInfo.GetCVESummaryForImage("repo3", "1.0.0")
		So(err, ShouldEqual, zerr.ErrTagMetaNotFound)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "")

		// Manifest is not found
		cveSummary, err = cveInfo.GetCVESummaryForImage("repo5", "nonexitent-manifest")
		So(err, ShouldEqual, zerr.ErrManifestDataNotFound)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "")

		// Repo is not found
		cveSummary, err = cveInfo.GetCVESummaryForImage("repo100", "1.0.0")
		So(err, ShouldEqual, zerr.ErrRepoMetaNotFound)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "")

		t.Log("Test GetCVEListForImage")

		pageInput := cveinfo.PageInput{
			SortBy: cveinfo.SeverityDsc,
		}

		// Image is found
		cveList, pageInfo, err := cveInfo.GetCVEListForImage("repo1", "0.1.0", "", pageInput)
		So(err, ShouldBeNil)
		So(len(cveList), ShouldEqual, 1)
		So(cveList[0].ID, ShouldEqual, "CVE1")
		So(pageInfo.ItemCount, ShouldEqual, 1)
		So(pageInfo.TotalCount, ShouldEqual, 1)

		cveList, pageInfo, err = cveInfo.GetCVEListForImage("repo1", "1.0.0", "", pageInput)
		So(err, ShouldBeNil)
		So(len(cveList), ShouldEqual, 3)
		So(cveList[0].ID, ShouldEqual, "CVE2")
		So(cveList[1].ID, ShouldEqual, "CVE1")
		So(cveList[2].ID, ShouldEqual, "CVE3")
		So(pageInfo.ItemCount, ShouldEqual, 3)
		So(pageInfo.TotalCount, ShouldEqual, 3)

		cveList, pageInfo, err = cveInfo.GetCVEListForImage("repo1", "1.0.1", "", pageInput)
		So(err, ShouldBeNil)
		So(len(cveList), ShouldEqual, 2)
		So(cveList[0].ID, ShouldEqual, "CVE1")
		So(cveList[1].ID, ShouldEqual, "CVE3")
		So(pageInfo.ItemCount, ShouldEqual, 2)
		So(pageInfo.TotalCount, ShouldEqual, 2)

		cveList, pageInfo, err = cveInfo.GetCVEListForImage("repo1", "1.1.0", "", pageInput)
		So(err, ShouldBeNil)
		So(len(cveList), ShouldEqual, 1)
		So(cveList[0].ID, ShouldEqual, "CVE3")
		So(pageInfo.ItemCount, ShouldEqual, 1)
		So(pageInfo.TotalCount, ShouldEqual, 1)

		cveList, pageInfo, err = cveInfo.GetCVEListForImage("repo6", "1.0.0", "", pageInput)
		So(err, ShouldBeNil)
		So(len(cveList), ShouldEqual, 0)
		So(pageInfo.ItemCount, ShouldEqual, 0)
		So(pageInfo.TotalCount, ShouldEqual, 0)

		// Image is not scannable
		cveList, pageInfo, err = cveInfo.GetCVEListForImage("repo2", "1.0.0", "", pageInput)
		So(err, ShouldEqual, zerr.ErrScanNotSupported)
		So(len(cveList), ShouldEqual, 0)
		So(pageInfo.ItemCount, ShouldEqual, 0)
		So(pageInfo.TotalCount, ShouldEqual, 0)

		// Tag is not found
		cveList, pageInfo, err = cveInfo.GetCVEListForImage("repo3", "1.0.0", "", pageInput)
		So(err, ShouldEqual, zerr.ErrTagMetaNotFound)
		So(len(cveList), ShouldEqual, 0)
		So(pageInfo.ItemCount, ShouldEqual, 0)
		So(pageInfo.TotalCount, ShouldEqual, 0)

		// Manifest is not found
		cveList, pageInfo, err = cveInfo.GetCVEListForImage("repo5", "nonexitent-manifest", "", pageInput)
		So(err, ShouldEqual, zerr.ErrManifestDataNotFound)
		So(len(cveList), ShouldEqual, 0)
		So(pageInfo.ItemCount, ShouldEqual, 0)
		So(pageInfo.TotalCount, ShouldEqual, 0)

		// Repo is not found
		cveList, pageInfo, err = cveInfo.GetCVEListForImage("repo100", "1.0.0", "", pageInput)
		So(err, ShouldEqual, zerr.ErrRepoMetaNotFound)
		So(len(cveList), ShouldEqual, 0)
		So(pageInfo.ItemCount, ShouldEqual, 0)
		So(pageInfo.TotalCount, ShouldEqual, 0)

		t.Log("Test GetImageListWithCVEFixed")

		// Image is found
		tagList, err := cveInfo.GetImageListWithCVEFixed("repo1", "CVE1")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 1)
		So(tagList[0].Name, ShouldEqual, "1.1.0")

		tagList, err = cveInfo.GetImageListWithCVEFixed("repo1", "CVE2")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 2)
		expectedTags := []string{"1.0.1", "1.1.0"}
		So(expectedTags, ShouldContain, tagList[0].Name)
		So(expectedTags, ShouldContain, tagList[1].Name)

		tagList, err = cveInfo.GetImageListWithCVEFixed("repo1", "CVE3")
		So(err, ShouldBeNil)
		// CVE3 is not present in 0.1.0, but that is older than all other
		// images where it is present. The rest of the images explicitly  have it.
		// This means we consider it not fixed in any image.
		So(len(tagList), ShouldEqual, 0)

		// Image doesn't have any CVEs in the first place
		tagList, err = cveInfo.GetImageListWithCVEFixed("repo6", "CVE1")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 1)
		So(tagList[0].Name, ShouldEqual, "1.0.0")

		// Image is not scannable
		tagList, err = cveInfo.GetImageListWithCVEFixed("repo2", "CVE100")
		// CVE is not considered fixed as scan is not possible
		// but do not return an error
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 0)

		// Tag is not found, but we should not error
		tagList, err = cveInfo.GetImageListWithCVEFixed("repo3", "CVE101")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 0)

		// Manifest is not found, we just consider exclude it from the fixed list
		tagList, err = cveInfo.GetImageListWithCVEFixed("repo5", "CVE101")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 0)

		// Repo is not found, there could potentially be unaffected tags in the repo
		// but we can't access their data
		tagList, err = cveInfo.GetImageListWithCVEFixed("repo100", "CVE100")
		So(err, ShouldEqual, zerr.ErrRepoMetaNotFound)
		So(len(tagList), ShouldEqual, 0)

		t.Log("Test GetImageListForCVE")

		// Image is found
		tagList, err = cveInfo.GetImageListForCVE("repo1", "CVE1")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 3)
		expectedTags = []string{"0.1.0", "1.0.0", "1.0.1"}
		So(expectedTags, ShouldContain, tagList[0].Name)
		So(expectedTags, ShouldContain, tagList[1].Name)
		So(expectedTags, ShouldContain, tagList[2].Name)

		tagList, err = cveInfo.GetImageListForCVE("repo1", "CVE2")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 1)
		So(tagList[0].Name, ShouldEqual, "1.0.0")

		tagList, err = cveInfo.GetImageListForCVE("repo1", "CVE3")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 3)
		expectedTags = []string{"1.0.0", "1.0.1", "1.1.0"}
		So(expectedTags, ShouldContain, tagList[0].Name)
		So(expectedTags, ShouldContain, tagList[1].Name)
		So(expectedTags, ShouldContain, tagList[2].Name)

		// Image/repo doesn't have the CVE at all
		tagList, err = cveInfo.GetImageListForCVE("repo6", "CVE1")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 0)

		// Image is not scannable
		tagList, err = cveInfo.GetImageListForCVE("repo2", "CVE100")
		// Image is not considered affected with CVE as scan is not possible
		// but do not return an error
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 0)

		// Tag is not found, but we should not error
		tagList, err = cveInfo.GetImageListForCVE("repo3", "CVE101")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 0)

		// Repo is not found, assume it is affetected by the CVE
		// But we don't have enough of it's data to actually return it
		tagList, err = cveInfo.GetImageListForCVE("repo100", "CVE100")
		So(err, ShouldEqual, zerr.ErrRepoMetaNotFound)
		So(len(tagList), ShouldEqual, 0)

		t.Log("Test errors while scanning")

		faultyScanner := mocks.CveScannerMock{
			ScanImageFn: func(image string) (map[string]cvemodel.CVE, error) {
				// Could be any type of error, let's reuse this one
				return nil, zerr.ErrScanNotSupported
			},
		}

		cveInfo = cveinfo.BaseCveInfo{Log: log, Scanner: faultyScanner, RepoDB: repoDB}

		cveSummary, err = cveInfo.GetCVESummaryForImage("repo1", "0.1.0")
		So(err, ShouldNotBeNil)
		So(cveSummary.Count, ShouldEqual, 0)
		So(cveSummary.MaxSeverity, ShouldEqual, "")

		cveList, pageInfo, err = cveInfo.GetCVEListForImage("repo1", "0.1.0", "", pageInput)
		So(err, ShouldNotBeNil)
		So(cveList, ShouldBeEmpty)
		So(pageInfo.ItemCount, ShouldEqual, 0)
		So(pageInfo.TotalCount, ShouldEqual, 0)

		tagList, err = cveInfo.GetImageListWithCVEFixed("repo1", "CVE1")
		// CVE is not considered fixed as scan is not possible
		// but do not return an error
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 0)

		tagList, err = cveInfo.GetImageListForCVE("repo1", "CVE1")
		// Image is not considered affected with CVE as scan is not possible
		// but do not return an error
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 0)

		cveInfo = cveinfo.BaseCveInfo{Log: log, Scanner: scanner, RepoDB: repoDB}

		tagList, err = cveInfo.GetImageListForCVE("repoIndex", "CVE1")
		So(err, ShouldBeNil)
		So(len(tagList), ShouldEqual, 0)

		cveInfo = cveinfo.BaseCveInfo{Log: log, Scanner: mocks.CveScannerMock{
			IsImageFormatScannableFn: func(repo, reference string) (bool, error) {
				return false, nil
			},
		}, RepoDB: repoDB}

		_, err = cveInfo.GetImageListForCVE("repoIndex", "CVE1")
		So(err, ShouldBeNil)

		cveInfo = cveinfo.BaseCveInfo{Log: log, Scanner: mocks.CveScannerMock{
			IsImageFormatScannableFn: func(repo, reference string) (bool, error) {
				return true, nil
			},
			ScanImageFn: func(image string) (map[string]cvemodel.CVE, error) {
				return nil, zerr.ErrTypeAssertionFailed
			},
		}, RepoDB: repoDB}

		_, err = cveInfo.GetImageListForCVE("repoIndex", "CVE1")
		So(err, ShouldBeNil)
	})
}

func getTags() ([]cvemodel.TagInfo, []cvemodel.TagInfo) {
	tags := make([]cvemodel.TagInfo, 0)

	firstTag := cvemodel.TagInfo{
		Name: "1.0.0",
		Descriptor: cvemodel.Descriptor{
			Digest:    "sha256:eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb",
			MediaType: ispec.MediaTypeImageManifest,
		},
		Timestamp: time.Now(),
	}
	secondTag := cvemodel.TagInfo{
		Name: "1.0.1",
		Descriptor: cvemodel.Descriptor{
			Digest:    "sha256:eca04f027f414362596f2632746d8a179362170b9ac9af772011fedcc3877ebb",
			MediaType: ispec.MediaTypeImageManifest,
		},
		Timestamp: time.Now(),
	}
	thirdTag := cvemodel.TagInfo{
		Name: "1.0.2",
		Descriptor: cvemodel.Descriptor{
			Digest:    "sha256:eca04f027f414362596f2632746d8a170362170b9ac9af772011fedcc3877ebb",
			MediaType: ispec.MediaTypeImageManifest,
		},
		Timestamp: time.Now(),
	}
	fourthTag := cvemodel.TagInfo{
		Name: "1.0.3",
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
			Name:       "taginfo",
			Descriptor: cvemodel.Descriptor{},
			Timestamp:  time.Date(2000, time.July, 20, 10, 10, 10, 10, time.UTC),
		}))
		So(len(fixedTags), ShouldEqual, 3)
	})
}
