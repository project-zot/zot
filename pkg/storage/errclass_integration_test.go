package storage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	bolt "go.etcd.io/bbolt"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	"zotregistry.dev/zot/v2/pkg/storage/gc"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/storageerrclass"
)

// These tests run the Missing / Transient / Permanent storage-class policy against
// real drivers. Missing always comes from the backend itself: the hook driver performs
// a real delete at the moment a concurrent writer could, or omits one live List entry.
// Transient and Permanent, which emulators cannot produce on demand, are injected as a
// single classified failure of one operation on one path on top of the real driver;
// on local, Permanent is also produced for real with chmod 000.
//
// errClassBackends is Local, S3, Azure and GCS (cloud backends skip without their
// emulator endpoints).
//
//nolint:gochecknoglobals
var errClassBackends = storageerrclass.Backends()

//nolint:gochecknoglobals
var injectedClasses = []struct {
	name  string
	class error
	mark  func(error) error
}{
	{"Transient", zerr.ErrStorageTransient, errclass.MarkTransient},
	{"Permanent", zerr.ErrStoragePermanent, errclass.MarkPermanent},
}

// errClassRepos is the walk fixture: "b" sits between two nested repositories, so a
// failure on it shows whether the walk stops or silently drops "c/repo".
//
//nolint:gochecknoglobals
var errClassRepos = []string{"a/repo", "b", "c/repo"}

var errInjected = errors.New("injected storage failure")

func writeErrClassRepos(storeController storage.StoreController) {
	for _, repo := range errClassRepos {
		So(WriteImageToFileSystem(CreateRandomImage(), repo, "v1", storeController), ShouldBeNil)
	}
}

// sweepRepositories drives GetNextRepository the way the GC / scrub generators do,
// calling visit on each repo. done is true only when the walk reported the end.
func sweepRepositories(imgStore storageTypes.ImageStore, processed map[string]struct{},
	visit func(repo string) error,
) (bool, error) {
	for range 10 {
		repo, err := imgStore.GetNextRepository(processed)
		if err != nil {
			return false, err
		}

		if repo == "" {
			return true, nil
		}

		if visit != nil {
			if err := visit(repo); err != nil {
				return false, err
			}
		}

		processed[repo] = struct{}{}
	}

	return false, nil
}

// skipIfRoot is for chmod-based cases: permission bits do not deny root.
func skipIfRoot() bool {
	return os.Geteuid() == 0
}

func gcIndexDigests(imgStore storageTypes.ImageStore) []godigest.Digest {
	content, err := imgStore.GetIndexContent(gcErrClassRepo)
	So(err, ShouldBeNil)

	var index ispec.Index
	So(json.Unmarshal(content, &index), ShouldBeNil)

	digests := make([]godigest.Digest, 0, len(index.Manifests))
	for _, desc := range index.Manifests {
		digests = append(digests, desc.Digest)
	}

	return digests
}

func TestErrClassRepositoryWalkIntegration(t *testing.T) {
	for _, backend := range errClassBackends {
		t.Run(backend.Name, func(t *testing.T) {
			Convey("A repository deleted while the walk is listing the store", t, func() {
				imgStore, hooks := storageerrclass.NewStore(t, backend)
				storeController := storage.StoreController{DefaultStore: imgStore}
				writeErrClassRepos(storeController)

				// Walk order is a, a/repo, b, c, c/repo: b vanishes after the root listing
				// already returned it and before the walk lists b itself.
				hooks.DeleteOnVisit = path.Join(imgStore.RootDir(), "b")

				Convey("GetRepositories never returns a partial list without an error", func() {
					repos, err := imgStore.GetRepositories()
					if backend.WalkAbortsOnNestedMissing {
						So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
						So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
						So(repos, ShouldBeEmpty)

						return
					}

					So(err, ShouldBeNil)
					So(repos, ShouldContain, "a/repo")
					So(repos, ShouldContain, "c/repo")
					So(repos, ShouldNotContain, "b")
				})

				Convey("a GetNextRepository sweep (GC/scrub generators) is not marked done early", func() {
					processed := map[string]struct{}{}
					done, err := sweepRepositories(imgStore, processed, nil)

					if backend.WalkAbortsOnNestedMissing {
						So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
						So(done, ShouldBeFalse)
						So(processed, ShouldContainKey, "a/repo")
						So(processed, ShouldNotContainKey, "c/repo")

						return
					}

					So(err, ShouldBeNil)
					So(done, ShouldBeTrue)
					So(processed, ShouldContainKey, "a/repo")
					So(processed, ShouldContainKey, "c/repo")
				})

				Convey("metaDB startup parse does not delete repos it never reached", func() {
					metaDB, err := boltdb.New(newBoltDriver(t), zlog.NewTestLogger())
					So(err, ShouldBeNil)

					// Seed metaDB from a full walk first (the hook is armed for b, so park it).
					target := hooks.DeleteOnVisit
					hooks.DeleteOnVisit = ""

					So(meta.ParseStorage(metaDB, storeController, zlog.NewTestLogger()), ShouldBeNil)

					names, err := metaDB.GetAllRepoNames()
					So(err, ShouldBeNil)
					So(names, ShouldContain, "c/repo")

					hooks.DeleteOnVisit = target
					err = meta.ParseStorage(metaDB, storeController, zlog.NewTestLogger())

					names, namesErr := metaDB.GetAllRepoNames()
					So(namesErr, ShouldBeNil)
					So(names, ShouldContain, "a/repo")
					So(names, ShouldContain, "c/repo")

					if backend.WalkAbortsOnNestedMissing {
						So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
					} else {
						So(err, ShouldBeNil)
					}

					// Once the store has settled, the next parse is complete and drops b.
					So(meta.ParseStorage(metaDB, storeController, zlog.NewTestLogger()), ShouldBeNil)

					names, err = metaDB.GetAllRepoNames()
					So(err, ShouldBeNil)
					So(names, ShouldNotContain, "b")
					So(names, ShouldContain, "a/repo")
					So(names, ShouldContain, "c/repo")
				})
			})

			for _, errCase := range injectedClasses {
				Convey("A "+errCase.name+" failure listing one repository candidate", t, func() {
					imgStore, hooks := storageerrclass.NewStore(t, backend)
					storeController := storage.StoreController{DefaultStore: imgStore}
					writeErrClassRepos(storeController)

					candidate := storageerrclass.Fault{
						Op: storageerrclass.OpList, Path: path.Join(imgStore.RootDir(), "b"), Err: errCase.mark(errInjected),
					}

					assertInventoryFailsClosed(t, imgStore, hooks, storeController, candidate, errCase.class)
				})

				if backend.IsLocal() {
					Convey("A "+errCase.name+" failure on a local repository's blobs/ Stat", t, func() {
						imgStore, hooks := storageerrclass.NewStore(t, backend)
						storeController := storage.StoreController{DefaultStore: imgStore}
						writeErrClassRepos(storeController)

						blobsStat := storageerrclass.Fault{
							Op:   storageerrclass.OpStat,
							Path: path.Join(imgStore.RootDir(), "b", ispec.ImageBlobsDir),
							Err:  errCase.mark(errInjected),
						}

						assertInventoryFailsClosed(t, imgStore, hooks, storeController, blobsStat, errCase.class)
					})
				}

				Convey("A "+errCase.name+" failure listing or walking the storage root", t, func() {
					imgStore, hooks := storageerrclass.NewStore(t, backend)
					storeController := storage.StoreController{DefaultStore: imgStore}
					writeErrClassRepos(storeController)

					metaDB, err := boltdb.New(newBoltDriver(t), zlog.NewTestLogger())
					So(err, ShouldBeNil)
					So(meta.ParseStorage(metaDB, storeController, zlog.NewTestLogger()), ShouldBeNil)

					root := imgStore.RootDir()
					hooks.AddFault(storageerrclass.Fault{Op: storageerrclass.OpList, Path: root, Err: errCase.mark(errInjected)})
					hooks.AddFault(storageerrclass.Fault{Op: storageerrclass.OpWalk, Path: root, Err: errCase.mark(errInjected)})

					_, err = imgStore.GetRepositories()
					So(errors.Is(err, errCase.class), ShouldBeTrue)

					repo, err := imgStore.GetNextRepository(map[string]struct{}{})
					So(errors.Is(err, errCase.class), ShouldBeTrue)
					So(repo, ShouldBeEmpty)

					err = meta.ParseStorage(metaDB, storeController, zlog.NewTestLogger())
					So(errors.Is(err, errCase.class), ShouldBeTrue)

					names, err := metaDB.GetAllRepoNames()
					So(err, ShouldBeNil)
					So(names, ShouldHaveLength, len(errClassRepos))
				})
			}

			if backend.SupportsRealPermanent && !skipIfRoot() {
				Convey("An unreadable repository directory (real Permanent)", t, func() {
					imgStore, _ := storageerrclass.NewStore(t, backend)
					storeController := storage.StoreController{DefaultStore: imgStore}
					writeErrClassRepos(storeController)

					unreadable := path.Join(imgStore.RootDir(), "b")
					So(os.Chmod(unreadable, 0o000), ShouldBeNil)

					Reset(func() { _ = os.Chmod(unreadable, 0o755) }) //nolint:gosec // restore test dir

					_, err := imgStore.GetRepositories()
					So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)

					done, err := sweepRepositories(imgStore, map[string]struct{}{}, nil)
					So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
					So(done, ShouldBeFalse)
				})
			}
		})
	}
}

// assertInventoryFailsClosed checks the inventory enumerators (GC / dedupe / scrub /
// metaDB parse) against a fault on repository candidate "b": each returns the fault's
// class instead of a listing that silently drops b, and completes once it clears.
func assertInventoryFailsClosed(t *testing.T, imgStore storageTypes.ImageStore, hooks *storageerrclass.HookDriver,
	storeController storage.StoreController, fault storageerrclass.Fault, class error,
) {
	t.Helper()

	Convey("GetRepositories returns the error instead of a list without b", func() {
		hooks.AddFault(fault)

		_, err := imgStore.GetRepositories()
		So(errors.Is(err, class), ShouldBeTrue)

		hooks.ClearFaults()

		repos, err := imgStore.GetRepositories()
		So(err, ShouldBeNil)
		So(repos, ShouldHaveLength, len(errClassRepos))
	})

	Convey("a GetNextRepository sweep stops, then completes once the fault clears", func() {
		hooks.AddFault(fault)

		processed := map[string]struct{}{}
		done, err := sweepRepositories(imgStore, processed, nil)
		So(errors.Is(err, class), ShouldBeTrue)
		So(done, ShouldBeFalse)
		So(processed, ShouldNotContainKey, "b")

		hooks.ClearFaults()

		done, err = sweepRepositories(imgStore, processed, nil)
		So(err, ShouldBeNil)
		So(done, ShouldBeTrue)

		for _, repo := range errClassRepos {
			So(processed, ShouldContainKey, repo)
		}
	})

	Convey("metaDB startup parse keeps every repo", func() {
		metaDB, err := boltdb.New(newBoltDriver(t), zlog.NewTestLogger())
		So(err, ShouldBeNil)
		So(meta.ParseStorage(metaDB, storeController, zlog.NewTestLogger()), ShouldBeNil)

		hooks.AddFault(fault)

		err = meta.ParseStorage(metaDB, storeController, zlog.NewTestLogger())
		So(errors.Is(err, class), ShouldBeTrue)

		names, err := metaDB.GetAllRepoNames()
		So(err, ShouldBeNil)

		for _, repo := range errClassRepos {
			So(names, ShouldContain, repo)
		}
	})
}

func TestErrClassCatalogIntegration(t *testing.T) {
	acceptAll := func(string) (bool, error) { return true, nil }

	for _, backend := range errClassBackends {
		t.Run(backend.Name, func(t *testing.T) {
			Convey("A repository deleted while the catalog walk is listing the store", t, func() {
				imgStore, hooks := storageerrclass.NewStore(t, backend)
				writeErrClassRepos(storage.StoreController{DefaultStore: imgStore})

				hooks.DeleteOnVisit = path.Join(imgStore.RootDir(), "b")

				repos, more, err := imgStore.GetNextRepositories("", 100, acceptAll)
				So(more, ShouldBeFalse)

				if backend.WalkAbortsOnNestedMissing {
					// A 503-class error, not a truncated catalog.
					So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
					So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
					So(repos, ShouldBeEmpty)

					return
				}

				So(err, ShouldBeNil)
				So(repos, ShouldContain, "a/repo")
				So(repos, ShouldContain, "c/repo")
			})

			for _, errCase := range injectedClasses {
				Convey("A "+errCase.name+" failure validating one catalog candidate is soft-skipped", t, func() {
					imgStore, hooks := storageerrclass.NewStore(t, backend)
					writeErrClassRepos(storage.StoreController{DefaultStore: imgStore})

					hooks.AddFault(storageerrclass.Fault{
						Op: storageerrclass.OpList, Path: path.Join(imgStore.RootDir(), "b"), Err: errCase.mark(errInjected),
					})

					repos, more, err := imgStore.GetNextRepositories("", 100, acceptAll)
					So(err, ShouldBeNil)
					So(more, ShouldBeFalse)
					So(repos, ShouldContain, "a/repo")
					So(repos, ShouldContain, "c/repo")
					So(repos, ShouldNotContain, "b")
				})

				Convey("A "+errCase.name+" failure walking the storage root fails the catalog", t, func() {
					imgStore, hooks := storageerrclass.NewStore(t, backend)
					writeErrClassRepos(storage.StoreController{DefaultStore: imgStore})

					hooks.AddFault(storageerrclass.Fault{
						Op: storageerrclass.OpWalk, Path: imgStore.RootDir(), Err: errCase.mark(errInjected),
					})

					repos, _, err := imgStore.GetNextRepositories("", 100, acceptAll)
					So(errors.Is(err, errCase.class), ShouldBeTrue)
					So(repos, ShouldBeEmpty)
				})
			}

			Convey("A Transient Stat probing the catalog last cursor still pages after it", t, func() {
				imgStore, hooks := storageerrclass.NewStore(t, backend)
				writeErrClassRepos(storage.StoreController{DefaultStore: imgStore})

				hooks.AddFault(storageerrclass.Fault{
					Op: storageerrclass.OpStat, Path: path.Join(imgStore.RootDir(), "b"),
					Err: errclass.MarkTransient(errInjected), Times: 1,
				})

				repos, more, err := imgStore.GetNextRepositories("b", 100, acceptAll)
				So(err, ShouldBeNil)
				So(more, ShouldBeFalse)
				So(repos, ShouldResemble, []string{"c/repo"})
			})

			if backend.SupportsRealPermanent && !skipIfRoot() {
				Convey("An unreadable repository directory (real Permanent) fails the catalog walk", t, func() {
					imgStore, _ := storageerrclass.NewStore(t, backend)
					writeErrClassRepos(storage.StoreController{DefaultStore: imgStore})

					unreadable := path.Join(imgStore.RootDir(), "b")
					So(os.Chmod(unreadable, 0o000), ShouldBeNil)

					Reset(func() { _ = os.Chmod(unreadable, 0o755) }) //nolint:gosec // restore test dir

					// Validate soft-skips b, but the walk itself must then list b to look for
					// nested repos, and that List fails: the catalog errors (HTTP 500) instead
					// of returning a page that silently omits b.
					_, _, err := imgStore.GetNextRepositories("", 100, acceptAll)
					So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
				})
			}
		})
	}
}

const gcErrClassRepo = "gc-errclass"

func TestErrClassGarbageCollectIntegration(t *testing.T) {
	const repo = gcErrClassRepo

	newGC := func(imgStore storageTypes.ImageStore, delay time.Duration) gc.GarbageCollect {
		return gc.NewGarbageCollect(imgStore, nil, gc.Options{
			Delay:          delay,
			ImageRetention: config.ImageRetention{Delay: time.Hour},
		}, zlog.NewAuditLogger("debug", "/dev/null"), zlog.NewTestLogger(),
			monitoring.NewNopMetricServer())
	}

	for _, backend := range errClassBackends {
		t.Run(backend.Name, func(t *testing.T) {
			Convey("GC on a repository with storage-level damage", t, func() {
				imgStore, hooks := storageerrclass.NewStore(t, backend)
				storeController := storage.StoreController{DefaultStore: imgStore}
				ctx := context.Background()

				keep := CreateRandomImage()
				stale := CreateRandomImage()
				So(WriteImageToFileSystem(keep, repo, "keep", storeController), ShouldBeNil)
				So(WriteImageToFileSystem(stale, repo, "stale", storeController), ShouldBeNil)

				gcInstance := newGC(imgStore, time.Hour)
				// Orphan blobs are age-eligible immediately, so "kept" below means GC chose
				// not to delete them rather than that they were too young.
				gcEager := newGC(imgStore, time.Nanosecond)

				repoDir := path.Join(imgStore.RootDir(), repo)
				indexPath := path.Join(repoDir, ispec.ImageIndexFile)
				staleManifest := storageerrclass.BlobPath(imgStore, repo, stale.ManifestDescriptor.Digest)

				uploadOrphan := func() godigest.Digest {
					content := []byte("orphan blob " + storageerrclass.NewUUID(t))
					digest := godigest.FromBytes(content)
					_, _, err := imgStore.FullBlobUpload(ctx, repo, bytes.NewReader(content), digest)
					So(err, ShouldBeNil)

					return digest
				}

				blobExists := func(digest godigest.Digest) bool {
					ok, _, _, err := imgStore.StatBlob(repo, digest)

					return err == nil && ok
				}

				Convey("a dangling index.json entry is pruned after Stat confirms Missing", func() {
					// An inventory miss alone is not enough; StatBlob must also report the
					// blob unavailable before the index row is dropped.
					So(hooks.Delete(staleManifest), ShouldBeNil)

					So(gcInstance.CleanRepo(ctx, repo), ShouldBeNil)

					digests := gcIndexDigests(imgStore)
					So(digests, ShouldNotContain, stale.ManifestDescriptor.Digest)
					So(digests, ShouldContain, keep.ManifestDescriptor.Digest)

					_, _, _, err := imgStore.GetImageManifest(repo, "keep")
					So(err, ShouldBeNil)
				})

				Convey("an inventory miss that Stat still finds keeps the index row", func() {
					// List omits a live manifest blob once (eventual consistency) while the
					// object remains; StatBlob sees it and must not prune.
					hooks.OmitListEntry = staleManifest

					So(gcInstance.CleanRepo(ctx, repo), ShouldBeNil)
					So(hooks.OmitListEntry, ShouldBeEmpty)

					digests := gcIndexDigests(imgStore)
					So(digests, ShouldContain, stale.ManifestDescriptor.Digest)
					So(digests, ShouldContain, keep.ManifestDescriptor.Digest)

					_, _, _, err := imgStore.GetImageManifest(repo, "stale")
					So(err, ShouldBeNil)
				})

				Convey("a tagged image with a missing layer is kept and the repo still finishes", func() {
					So(hooks.Delete(storageerrclass.BlobPath(imgStore, repo, keep.Manifest.Layers[0].Digest)), ShouldBeNil)

					So(gcInstance.CleanRepo(ctx, repo), ShouldBeNil)

					digests := gcIndexDigests(imgStore)
					So(digests, ShouldContain, keep.ManifestDescriptor.Digest)
					So(digests, ShouldContain, stale.ManifestDescriptor.Digest)
				})

				Convey("an incomplete blob inventory aborts the prune instead of pruning live rows", func() {
					// A second algorithm directory gives GetAllBlobs a nested List to lose.
					content := []byte("sha512 blob for a second algorithm directory")
					sha512Digest := godigest.SHA512.FromBytes(content)
					_, _, err := imgStore.FullBlobUpload(ctx, repo, bytes.NewReader(content), sha512Digest)
					So(err, ShouldBeNil)

					// The dangling row must survive while the inventory cannot be trusted.
					So(hooks.Delete(staleManifest), ShouldBeNil)

					blobsDir := path.Join(repoDir, ispec.ImageBlobsDir)
					hooks.DeleteAfterListOf = blobsDir
					hooks.DeleteTarget = path.Join(blobsDir, godigest.SHA512.String())

					err = gcInstance.CleanRepo(ctx, repo)
					So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
					So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
					So(hooks.DeleteAfterListOf, ShouldBeEmpty)

					digests := gcIndexDigests(imgStore)
					So(digests, ShouldContain, stale.ManifestDescriptor.Digest)
					So(digests, ShouldContain, keep.ManifestDescriptor.Digest)

					Convey("and the next run, with a consistent listing, prunes it", func() {
						So(gcInstance.CleanRepo(ctx, repo), ShouldBeNil)

						digests := gcIndexDigests(imgStore)
						So(digests, ShouldNotContain, stale.ManifestDescriptor.Digest)
						So(digests, ShouldContain, keep.ManifestDescriptor.Digest)
					})
				})

				for _, errCase := range injectedClasses {
					Convey("a "+errCase.name+" index.json read fails CleanRepo without deleting anything", func() {
						So(hooks.Delete(staleManifest), ShouldBeNil)
						orphan := uploadOrphan()

						hooks.AddFault(storageerrclass.Fault{
							Op: storageerrclass.OpReadFile, Path: indexPath, Err: errCase.mark(errInjected),
						})

						err := gcEager.CleanRepo(ctx, repo)
						So(errors.Is(err, errCase.class), ShouldBeTrue)
						So(errors.Is(err, zerr.ErrRepoNotFound), ShouldBeFalse)

						hooks.ClearFaults()

						So(gcIndexDigests(imgStore), ShouldContain, stale.ManifestDescriptor.Digest)
						So(blobExists(orphan), ShouldBeTrue)
					})

					Convey("a "+errCase.name+" blobs/ List aborts before pruning rows or orphans", func() {
						So(hooks.Delete(staleManifest), ShouldBeNil)
						orphan := uploadOrphan()

						hooks.AddFault(storageerrclass.Fault{
							Op: storageerrclass.OpList, Path: path.Join(repoDir, ispec.ImageBlobsDir), Err: errCase.mark(errInjected),
						})

						err := gcEager.CleanRepo(ctx, repo)
						So(errors.Is(err, errCase.class), ShouldBeTrue)

						hooks.ClearFaults()

						So(gcIndexDigests(imgStore), ShouldContain, stale.ManifestDescriptor.Digest)
						So(blobExists(orphan), ShouldBeTrue)
					})

					Convey("a "+errCase.name+" Stat confirming a dangling row aborts the prune", func() {
						So(hooks.Delete(staleManifest), ShouldBeNil)

						hooks.AddFault(storageerrclass.Fault{
							Op: storageerrclass.OpStat, Path: staleManifest, Err: errCase.mark(errInjected),
						})

						err := gcInstance.CleanRepo(ctx, repo)
						So(errors.Is(err, errCase.class), ShouldBeTrue)

						hooks.ClearFaults()

						So(gcIndexDigests(imgStore), ShouldContain, stale.ManifestDescriptor.Digest)
					})

					Convey("a "+errCase.name+" .uploads List fails CleanRepo", func() {
						hooks.AddFault(storageerrclass.Fault{
							Op:   storageerrclass.OpList,
							Path: path.Join(repoDir, storageConstants.BlobUploadDir),
							Err:  errCase.mark(errInjected),
						})

						err := gcInstance.CleanRepo(ctx, repo)
						So(errors.Is(err, errCase.class), ShouldBeTrue)
					})

					Convey("a "+errCase.name+" index.json read fails RemoveIdleRepository and keeps the repo", func() {
						hooks.AddFault(storageerrclass.Fault{
							Op: storageerrclass.OpReadFile, Path: indexPath, Err: errCase.mark(errInjected),
						})

						removed, err := imgStore.RemoveIdleRepository(repo, 0)
						So(errors.Is(err, errCase.class), ShouldBeTrue)
						So(removed, ShouldBeFalse)

						hooks.ClearFaults()

						So(gcIndexDigests(imgStore), ShouldHaveLength, 2)
					})
				}

				Convey("a Transient age Stat skips that orphan and GC still reaps the others", func() {
					skipped := uploadOrphan()
					reaped := uploadOrphan()

					hooks.AddFault(storageerrclass.Fault{
						Op: storageerrclass.OpStat, Path: storageerrclass.BlobPath(imgStore, repo, skipped),
						Err: errclass.MarkTransient(errInjected),
					})

					So(gcEager.CleanRepo(ctx, repo), ShouldBeNil)

					hooks.ClearFaults()

					So(blobExists(skipped), ShouldBeTrue)
					So(blobExists(reaped), ShouldBeFalse)
					So(gcIndexDigests(imgStore), ShouldHaveLength, 2)
				})
			})

			for _, errCase := range injectedClasses {
				Convey("A GC sweep over the store with a "+errCase.name+" failure on one repository", t, func() {
					imgStore, hooks := storageerrclass.NewStore(t, backend)
					writeErrClassRepos(storage.StoreController{DefaultStore: imgStore})

					ctx := context.Background()
					gcInstance := newGC(imgStore, time.Hour)
					cleanRepo := func(repo string) error { return gcInstance.CleanRepo(ctx, repo) }

					hooks.AddFault(storageerrclass.Fault{
						Op: storageerrclass.OpList, Path: path.Join(imgStore.RootDir(), "b"), Err: errCase.mark(errInjected),
					})

					processed := map[string]struct{}{}
					done, err := sweepRepositories(imgStore, processed, cleanRepo)
					So(errors.Is(err, errCase.class), ShouldBeTrue)
					So(done, ShouldBeFalse)
					So(processed, ShouldNotContainKey, "b")

					hooks.ClearFaults()

					done, err = sweepRepositories(imgStore, processed, cleanRepo)
					So(err, ShouldBeNil)
					So(done, ShouldBeTrue)

					for _, repo := range errClassRepos {
						So(processed, ShouldContainKey, repo)
					}
				})
			}
		})
	}
}

// TestErrClassBlobIOIntegration covers product paths that call storeDriver.Reader /
// Delete (GetBlob / DeleteBlob). Inventory and GC cases already inject OpReadFile /
// OpList / OpStat; OpReader and OpDelete were only exercised by the HookDriver unit
// test until this suite.
func TestErrClassBlobIOIntegration(t *testing.T) {
	const repo = "blob-io-errclass"

	for _, backend := range errClassBackends {
		t.Run(backend.Name, func(t *testing.T) {
			Convey("Blob Reader and Delete honor injected storage classes", t, func() {
				imgStore, hooks := storageerrclass.NewStore(t, backend)
				storeController := storage.StoreController{DefaultStore: imgStore}
				ctx := context.Background()

				img := CreateRandomImage()
				So(WriteImageToFileSystem(img, repo, "v1", storeController), ShouldBeNil)

				layerDigest := img.Manifest.Layers[0].Digest
				layerPath := storageerrclass.BlobPath(imgStore, repo, layerDigest)

				uploadOrphan := func() godigest.Digest {
					content := []byte("orphan blob " + storageerrclass.NewUUID(t))
					digest := godigest.FromBytes(content)
					_, _, err := imgStore.FullBlobUpload(ctx, repo, bytes.NewReader(content), digest)
					So(err, ShouldBeNil)

					return digest
				}

				for _, errCase := range injectedClasses {
					Convey("GetBlob propagates a "+errCase.name+" Reader failure", func() {
						hooks.AddFault(storageerrclass.Fault{
							Op: storageerrclass.OpReader, Path: layerPath, Err: errCase.mark(errInjected), Times: 1,
						})

						_, _, err := imgStore.GetBlob(repo, layerDigest, ispec.MediaTypeImageLayer)
						So(errors.Is(err, errCase.class), ShouldBeTrue)
						So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeFalse)

						rc, size, err := imgStore.GetBlob(repo, layerDigest, ispec.MediaTypeImageLayer)
						So(err, ShouldBeNil)
						So(size, ShouldBeGreaterThan, int64(0))
						So(rc.Close(), ShouldBeNil)
					})

					Convey("DeleteBlob propagates a "+errCase.name+" Delete failure", func() {
						// Referenced layers refuse DeleteBlob before the driver is called.
						orphan := uploadOrphan()
						orphanPath := storageerrclass.BlobPath(imgStore, repo, orphan)

						hooks.AddFault(storageerrclass.Fault{
							Op: storageerrclass.OpDelete, Path: orphanPath, Err: errCase.mark(errInjected), Times: 1,
						})

						err := imgStore.DeleteBlob(repo, orphan)
						So(errors.Is(err, errCase.class), ShouldBeTrue)

						ok, _, _, err := imgStore.StatBlob(repo, orphan)
						So(err, ShouldBeNil)
						So(ok, ShouldBeTrue)

						hooks.ClearFaults()
						So(imgStore.DeleteBlob(repo, orphan), ShouldBeNil)

						ok, _, _, err = imgStore.StatBlob(repo, orphan)
						So(err, ShouldNotBeNil)
						So(ok, ShouldBeFalse)
					})
				}

				Convey("DeleteBlob soft-skips when Delete reports Missing", func() {
					orphan := uploadOrphan()
					orphanPath := storageerrclass.BlobPath(imgStore, repo, orphan)

					hooks.AddFault(storageerrclass.Fault{
						Op: storageerrclass.OpDelete, Path: orphanPath,
						Err: errclass.MarkMissing(errInjected), Times: 1,
					})

					So(imgStore.DeleteBlob(repo, orphan), ShouldBeNil)

					ok, _, _, err := imgStore.StatBlob(repo, orphan)
					So(err, ShouldBeNil)
					So(ok, ShouldBeTrue)
				})
			})
		})
	}
}

func TestErrClassScrubIntegration(t *testing.T) {
	const repo = "scrub-errclass"

	for _, backend := range errClassBackends {
		t.Run(backend.Name, func(t *testing.T) {
			Convey("Scrub separates a vanished manifest from a damaged image", t, func() {
				imgStore, hooks := storageerrclass.NewStore(t, backend)
				storeController := storage.StoreController{DefaultStore: imgStore}

				good := CreateRandomImage()
				gone := CreateRandomImage()
				broken := CreateRandomImage()

				for tag, img := range map[string]Image{"good": good, "gone": gone, "broken": broken} {
					So(WriteImageToFileSystem(img, repo, tag, storeController), ShouldBeNil)
				}

				// A top-level manifest removed after index.json was read is a concurrent
				// delete (soft-skip); a missing layer under a readable manifest is damage.
				So(hooks.Delete(storageerrclass.BlobPath(imgStore, repo, gone.ManifestDescriptor.Digest)), ShouldBeNil)
				brokenLayer := broken.Manifest.Layers[0].Digest
				So(hooks.Delete(storageerrclass.BlobPath(imgStore, repo, brokenLayer)), ShouldBeNil)

				results, err := storage.CheckRepo(context.Background(), repo, imgStore)
				So(err, ShouldBeNil)

				byTag := map[string]storage.ScrubImageResult{}
				for _, result := range results {
					byTag[result.Tag] = result
				}

				So(byTag, ShouldNotContainKey, "gone")
				So(byTag["good"].Status, ShouldEqual, "ok")
				So(byTag["broken"].Status, ShouldEqual, "affected")
				So(byTag["broken"].AffectedBlob, ShouldEqual, brokenLayer.Encoded())
			})
		})
	}
}

func newBoltDriver(t *testing.T) *bolt.DB {
	t.Helper()

	boltDriver, err := boltdb.GetBoltDriver(boltdb.DBParameters{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = boltDriver.Close() })

	return boltDriver
}
