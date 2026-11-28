package meta_test

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/alicebob/miniredis/v2"
	godigest "github.com/opencontainers/go-digest"

	rediscfg "zotregistry.dev/zot/v2/pkg/api/config/redis"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	"zotregistry.dev/zot/v2/pkg/meta/redis"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	testimage "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

const (
	benchTagsEnv     = "ZOT_BENCH_TAGS"
	benchDefaultTags = 1000
	benchRepo        = "bench"
)

func benchTagCount(b *testing.B) int {
	b.Helper()

	value, found := os.LookupEnv(benchTagsEnv)
	if !found {
		return benchDefaultTags
	}

	count, err := strconv.Atoi(value)
	if err != nil || count < 1 {
		b.Fatalf("%s must be a positive number, got %q", benchTagsEnv, value)
	}

	return count
}

// benchReferences builds count references that differ in tag and digest, sharing one manifest body.
func benchReferences(count int) []mTypes.RepoReference {
	template := testimage.CreateRandomImage().AsImageMeta()
	references := make([]mTypes.RepoReference, 0, count)

	for i := range count {
		imageMeta := template
		imageMeta.Digest = godigest.FromString(fmt.Sprintf("bench-image-%d", i))
		imageMeta.Manifests = []mTypes.ManifestMeta{template.Manifests[0]}
		imageMeta.Manifests[0].Digest = imageMeta.Digest

		references = append(references, mTypes.RepoReference{
			Reference: fmt.Sprintf("tag-%d", i),
			ImageMeta: imageMeta,
		})
	}

	return references
}

// benchMetaDB opens an empty metaDB of the named flavour and returns it with its cleanup.
func benchMetaDB(b *testing.B, backend string) (mTypes.MetaDB, func()) {
	b.Helper()

	logger := log.NewTestLogger()

	switch backend {
	case "boltdb":
		boltDB, err := boltdb.GetBoltDriver(boltdb.DBParameters{RootDir: b.TempDir()})
		if err != nil {
			b.Fatalf("open boltdb: %v", err)
		}

		metaDB, err := boltdb.New(boltDB, logger)
		if err != nil {
			b.Fatalf("create boltdb metaDB: %v", err)
		}

		return metaDB, func() { _ = boltDB.Close() }
	case "miniredis":
		miniRedis, err := miniredis.Run()
		if err != nil {
			b.Fatalf("run miniredis: %v", err)
		}

		client, err := rediscfg.GetRedisClient(map[string]any{"url": "redis://" + miniRedis.Addr()}, logger)
		if err != nil {
			b.Fatalf("create redis client: %v", err)
		}

		metaDB, err := redis.New(client, redis.DBDriverParameters{KeyPrefix: "zot"}, logger)
		if err != nil {
			b.Fatalf("create redis metaDB: %v", err)
		}

		return metaDB, func() { miniRedis.Close() }
	default:
		b.Fatalf("unknown backend %q", backend)

		return nil, nil
	}
}

func BenchmarkParseRepoMetaDB(b *testing.B) {
	references := benchReferences(benchTagCount(b))
	ctx := context.Background()

	modes := map[string]func(metaDB mTypes.MetaDB) error{
		"sequential": func(metaDB mTypes.MetaDB) error {
			for _, reference := range references {
				err := metaDB.SetRepoReference(ctx, benchRepo, reference.Reference, reference.ImageMeta, reference.Opts...)
				if err != nil {
					return err
				}
			}

			return nil
		},
		"batch": func(metaDB mTypes.MetaDB) error {
			for start := 0; start < len(references); start += meta.ParseChunkSize {
				chunk := references[start:min(start+meta.ParseChunkSize, len(references))]

				if err := metaDB.SetRepoReferences(ctx, benchRepo, chunk); err != nil {
					return err
				}
			}

			return nil
		},
	}

	for _, backend := range []string{"boltdb", "miniredis"} {
		b.Run(backend, func(b *testing.B) {
			for _, mode := range []string{"sequential", "batch"} {
				b.Run(mode, func(b *testing.B) {
					for range b.N {
						b.StopTimer()

						metaDB, cleanup := benchMetaDB(b, backend)

						b.StartTimer()

						err := modes[mode](metaDB)

						b.StopTimer()
						cleanup()

						if err != nil {
							b.Fatalf("write references: %v", err)
						}
					}
				})
			}
		})
	}
}
