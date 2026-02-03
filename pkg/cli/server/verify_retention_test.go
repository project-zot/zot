package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	cli "zotregistry.dev/zot/v2/pkg/cli/server"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	"zotregistry.dev/zot/v2/pkg/meta/redis"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

const (
	decisionKeep             = "keep"
	decisionDelete           = "delete"
	retentionTestRepo        = "retention-test-repo"
	retentionTestRepoSubpath = "a/retention-test-repo"
	testGCDelay              = "1ms"
)

func TestRetentionCheckNegative(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test verify-feature retention no args", t, func(c C) {
		os.Args = []string{"cli_test", "verify-feature", "retention"}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("non-existent config", t, func(c C) {
		tempDir := t.TempDir()
		os.Args = []string{"cli_test", "verify-feature", "retention", path.Join(tempDir, "/x.yaml")}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("unknown config", t, func(c C) {
		tempDir := t.TempDir()
		os.Args = []string{"cli_test", "verify-feature", "retention", path.Join(tempDir, "/x")}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("bad config", t, func(c C) {
		configFile := MakeTempFileWithContent(t, "zot-config.json", `{"log":{}}`)

		os.Args = []string{"cli_test", "verify-feature", "retention", "-t", "30s", configFile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("config with GC disabled", t, func(c C) {
		testDir := t.TempDir()
		logFile := MakeTempFilePath(t, "retention-check.log")
		port := GetFreePort()

		content := fmt.Sprintf(`{
			"distSpecVersion": "1.1.1",
			"storage": {
				"rootDirectory": "%s",
				"gc": false
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			}
		}`, testDir, port)
		configFile := MakeTempFileWithContent(t, "zot-config.json", content)

		os.Args = []string{"cli_test", "verify-feature", "retention", "-l", logFile, "-t", "30s", configFile}
		err := cli.NewServerRootCmd().Execute()

		// Verify the specific error
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual,
			fmt.Sprintf("%s: %s", zerr.ErrBadConfig.Error(), "verify-feature retention requires GC to be enabled"))

		// Verify error message is logged to the log file
		logContent, err := os.ReadFile(logFile)
		So(err, ShouldBeNil)
		logStr := string(logContent)
		So(logStr, ShouldContainSubstring,
			"failed to run verify-feature retention, garbage collection is disabled in config")
	})

	Convey("server is running", t, func(c C) {
		port := GetFreePort()
		config := config.New()
		config.HTTP.Port = port
		controller := api.NewController(config)

		testDir := t.TempDir()
		storageDir := path.Join(testDir, "storage")
		logFile := MakeTempFilePath(t, "retention-check.log")

		controller.Config.Storage.RootDirectory = storageDir
		controller.Config.Storage.GC = true
		ctrlManager := NewControllerManager(controller)
		ctrlManager.StartAndWait(port)

		defer ctrlManager.StopServer()

		content := fmt.Sprintf(`{
			"storage": {
				"rootDirectory": "%s",
				"gc": true,
				"retention": {
					"delay": "1ms",
					"policies": [
						{
							"repositories": ["**"],
							"keepTags": [
								{
									"patterns": [".*"],
									"mostRecentlyPulledCount": 5
								}
							]
						}
					]
				}
			},
			"http": {
				"port": %s
			},
			"log": {
				"level": "debug"
			}
		}
		`, storageDir, port)
		configFile := MakeTempFileWithContent(t, "zot-config.json", content)

		os.Args = []string{"cli_test", "verify-feature", "retention", "-l", logFile, "-t", "30s", configFile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		// Check that error indicates binding failure (server is running)
		So(err.Error(), ShouldContainSubstring, "failed to bind")

		// Verify warning and error messages are logged to the log file
		logContent, err := os.ReadFile(logFile)
		So(err, ShouldBeNil)
		So(string(logContent), ShouldContainSubstring,
			"local storage detected - the zot server must be stopped to access the storage database")
		So(string(logContent), ShouldContainSubstring,
			"failed to bind")
	})

	Convey("invalid address format", t, func(c C) {
		testDir := t.TempDir()
		logFile := MakeTempFilePath(t, "retention-check.log")
		port := GetFreePort()

		// Use an invalid IPv6 address format that will pass LoadConfiguration
		// but fail net.ResolveTCPAddr immediately (syntax error, no DNS lookup)
		content := fmt.Sprintf(`{
			"distSpecVersion": "1.1.1",
			"storage": {
				"rootDirectory": "%s",
				"gc": true
			},
			"http": {
				"address": "[invalid:ipv6",
				"port": "%s"
			},
			"log": {
				"level": "debug"
			}
		}`, testDir, port)
		configFile := MakeTempFileWithContent(t, "zot-config.json", content)

		os.Args = []string{"cli_test", "verify-feature", "retention", "-l", logFile, "-t", "30s", configFile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		// Check that error indicates TCP address resolution failure
		So(err.Error(), ShouldContainSubstring, "failed to resolve TCP address")

		// Verify error message is logged to the log file
		logContent, err := os.ReadFile(logFile)
		So(err, ShouldBeNil)
		So(string(logContent), ShouldContainSubstring,
			"local storage detected - the zot server must be stopped to access the storage database")
		So(string(logContent), ShouldContainSubstring,
			"failed to resolve TCP address")
	})

	Convey("invalid log-file flag", t, func(c C) {
		testCases := []struct {
			name    string
			logFile string
		}{
			{"invalid log file path (parent directory doesn't exist)", "/invalid/directory/logfile.log"},
			{"invalid log file path (null bytes)", "logfile\x00.log"},
		}

		for _, testCase := range testCases {
			Convey(testCase.name, func() {
				testDir := t.TempDir()
				port := GetFreePort()

				content := fmt.Sprintf(`{
					"distSpecVersion": "1.1.1",
					"storage": {
						"rootDirectory": "%s",
						"gc": true
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s"
					}
				}`, testDir, port)
				configFile := MakeTempFileWithContent(t, "zot-config.json", content)

				os.Args = []string{"cli_test", "verify-feature", "retention", "-l", testCase.logFile, "-t", "30s", configFile}
				// This panics during logger initialization due to invalid log file location
				So(func() {
					_ = cli.NewServerRootCmd().Execute()
				}, ShouldPanic)
			})
		}
	})

	Convey("invalid duration flags", t, func(c C) {
		testCases := []struct {
			name      string
			flag      string
			flagValue string
		}{
			{"invalid gc-interval flag", "-i", "invalid-duration"},
			{"invalid timeout flag", "-t", "invalid-duration"},
		}

		for _, testCase := range testCases {
			Convey(testCase.name, func() {
				testDir := t.TempDir()
				logFile := MakeTempFilePath(t, "retention-check.log")
				port := GetFreePort()

				content := fmt.Sprintf(`{
					"distSpecVersion": "1.1.1",
					"storage": {
						"rootDirectory": "%s",
						"gc": true
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s"
					}
				}`, testDir, port)
				configFile := MakeTempFileWithContent(t, "zot-config.json", content)

				args := []string{
					"cli_test", "verify-feature", "retention", "-l", logFile,
					testCase.flag, testCase.flagValue,
				}

				if testCase.flag == "-i" {
					args = append(args, "-t", "30s")
				}

				args = append(args, configFile)
				os.Args = args

				err := cli.NewServerRootCmd().Execute()
				// Flag parsing should fail before reaching RunE
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "invalid duration")
			})
		}
	})
}

func TestRetentionCheckWithRetentionEnabledAndRedisDriver(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("server is running with Redis driver", t, func(c C) {
		miniRedis := miniredis.RunT(t)
		port := GetFreePort()
		testDir := t.TempDir()
		storageDir := path.Join(testDir, "storage")
		logFile := MakeTempFilePath(t, "retention-check.log")

		content := fmt.Sprintf(`{
			"distSpecVersion": "1.1.1",
			"storage": {
				"rootDirectory": "%s",
				"gc": true,
				"remoteCache": true,
				"gcDelay": %q,
				"gcInterval": "1m",
				"cacheDriver": {
					"name": "redis",
					"url": "redis://%s"
				},
				"retention": {
					"delay": "1ms",
					"policies": [
						{
							"repositories": ["**"],
							"keepTags": [
								{
									"patterns": [".*"],
									"mostRecentlyPulledCount": 2
								}
							]
						}
					]
				}
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			},
			"log": {
				"level": "debug"
			}
		}
		`, storageDir, testGCDelay, miniRedis.Addr(), port)
		configFile := MakeTempFileWithContent(t, "zot-config.json", content)

		// Create complex image setup before running verify-feature retention
		conf := config.New()
		err := cli.LoadConfiguration(conf, configFile)
		So(err, ShouldBeNil)

		// Initialize storage and metaDB using the same approach as gc tests
		metricsServer := monitoring.NewMetricsServer(false, zlog.NewLogger("info", ""))
		// Create ImageStore directly (like gc tests)
		imgStore := local.NewImageStore(storageDir, false, false, zlog.NewLogger("info", ""), metricsServer,
			nil, nil, nil, nil)
		// Initialize metaDB with Redis
		redisClient := goredis.NewClient(&goredis.Options{
			Addr: miniRedis.Addr(),
		})
		params := redis.DBDriverParameters{KeyPrefix: "zot"}
		metaDB, err := redis.New(redisClient, params, zlog.NewLogger("info", ""))
		So(err, ShouldBeNil)
		// Create store controller
		storeController := storage.StoreController{}
		storeController.DefaultStore = imgStore
		err = meta.ParseStorage(metaDB, storeController, zlog.NewLogger("info", ""))
		So(err, ShouldBeNil)

		// Create test repositories with different image types for retention testing
		// Repository 1: Multiple tagged images (some old, some recent)
		repo1 := retentionTestRepo

		// Old image (should be deleted by retention - keeping only 2 most recent)
		oldImage := CreateRandomImage()
		err = WriteImageToFileSystem(oldImage, repo1, "old-tag", storeController)
		So(err, ShouldBeNil)

		// Recent images (should be kept)
		recentImage1 := CreateRandomImage()
		err = WriteImageToFileSystem(recentImage1, repo1, "recent-tag-1", storeController)
		So(err, ShouldBeNil)

		recentImage2 := CreateRandomImage()
		err = WriteImageToFileSystem(recentImage2, repo1, "recent-tag-2", storeController)
		So(err, ShouldBeNil)

		// Multiarch image
		multiarchImage := CreateRandomMultiarch()
		err = WriteMultiArchImageToFileSystem(multiarchImage, repo1, "multiarch-tag", storeController)
		So(err, ShouldBeNil)

		// Untagged image (should be cleaned up by GC)
		untaggedImage := CreateRandomImage()
		err = WriteImageToFileSystem(untaggedImage, repo1, untaggedImage.DigestStr(), storeController)
		So(err, ShouldBeNil)

		// Repository 2: Referrers
		repo2 := "referrer-test-repo"

		// Base image
		baseImage := CreateRandomImage()
		err = WriteImageToFileSystem(baseImage, repo2, "base-tag", storeController)
		So(err, ShouldBeNil)

		// Referrer pointing to base image
		referrer := CreateRandomImageWith().Subject(baseImage.DescriptorRef()).Build()
		err = WriteImageToFileSystem(referrer, repo2, referrer.DigestStr(), storeController)
		So(err, ShouldBeNil)

		// Referrer pointing to non-existent subject (should be deleted)
		nonExistentSubject := CreateRandomImage() // Create but don't write to storage
		referrerWithInvalidSubject := CreateRandomImageWith().Subject(nonExistentSubject.DescriptorRef()).Build()
		err = WriteImageToFileSystem(referrerWithInvalidSubject, repo2,
			referrerWithInvalidSubject.DigestStr(), storeController)
		So(err, ShouldBeNil)

		// Re-parse storage after creating images to update metadata
		err = meta.ParseStorage(metaDB, storeController, zlog.NewLogger("info", ""))
		So(err, ShouldBeNil)

		// Update metadata with timestamps for retention testing
		// Set old timestamps for images that should be deleted
		repoMeta1, err := metaDB.GetRepoMeta(context.Background(), repo1)
		So(err, ShouldBeNil)

		// Old images (should be deleted by retention - keeping only 2 most recent)
		oldImageStats := repoMeta1.Statistics[oldImage.DigestStr()]
		oldImageStats.PushTimestamp = time.Now().Add(-10 * 24 * time.Hour)
		oldImageStats.LastPullTimestamp = time.Now().Add(-10 * 24 * time.Hour)
		repoMeta1.Statistics[oldImage.DigestStr()] = oldImageStats

		// Recent images (should be kept)
		recentImage1Stats := repoMeta1.Statistics[recentImage1.DigestStr()]
		recentImage1Stats.PushTimestamp = time.Now().Add(-1 * 24 * time.Hour)
		recentImage1Stats.LastPullTimestamp = time.Now().Add(-1 * 24 * time.Hour)
		repoMeta1.Statistics[recentImage1.DigestStr()] = recentImage1Stats

		recentImage2Stats := repoMeta1.Statistics[recentImage2.DigestStr()]
		recentImage2Stats.PushTimestamp = time.Now().Add(-2 * 24 * time.Hour)
		recentImage2Stats.LastPullTimestamp = time.Now().Add(-2 * 24 * time.Hour)
		repoMeta1.Statistics[recentImage2.DigestStr()] = recentImage2Stats

		multiarchStats := repoMeta1.Statistics[multiarchImage.DigestStr()]
		multiarchStats.PushTimestamp = time.Now().Add(-3 * 24 * time.Hour)
		multiarchStats.LastPullTimestamp = time.Now().Add(-3 * 24 * time.Hour)
		repoMeta1.Statistics[multiarchImage.DigestStr()] = multiarchStats

		err = metaDB.SetRepoMeta(repo1, repoMeta1)
		So(err, ShouldBeNil)

		// Set timestamps for referrer repo
		repoMeta2, err := metaDB.GetRepoMeta(context.Background(), repo2)
		So(err, ShouldBeNil)

		baseImageStats := repoMeta2.Statistics[baseImage.DigestStr()]
		baseImageStats.PushTimestamp = time.Now().Add(-5 * 24 * time.Hour)
		baseImageStats.LastPullTimestamp = time.Now().Add(-5 * 24 * time.Hour)
		repoMeta2.Statistics[baseImage.DigestStr()] = baseImageStats

		referrerStats := repoMeta2.Statistics[referrer.DigestStr()]
		referrerStats.PushTimestamp = time.Now().Add(-4 * 24 * time.Hour)
		referrerStats.LastPullTimestamp = time.Now().Add(-4 * 24 * time.Hour)
		repoMeta2.Statistics[referrer.DigestStr()] = referrerStats

		err = metaDB.SetRepoMeta(repo2, repoMeta2)
		So(err, ShouldBeNil)

		// Close metaDB to release database lock before running verify-feature retention
		err = metaDB.Close()
		So(err, ShouldBeNil)

		gcDelay, _ := time.ParseDuration(testGCDelay)
		time.Sleep(gcDelay + 50*time.Millisecond) // wait for GC delay to pass

		// Start a controller using the same config to test running verify-feature retention while server is running
		controller := api.NewController(conf)
		ctrlManager := NewControllerManager(controller)
		ctrlManager.StartAndWait(port)

		defer ctrlManager.StopServer()

		os.Args = []string{"cli_test", "verify-feature", "retention", "-l", logFile, "-t", "2s", configFile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)

		// Verify success messages are logged to the log file
		logContent, err := os.ReadFile(logFile)
		So(err, ShouldBeNil)
		logStr := string(logContent)

		// Dump log content to stdout on test failure
		defer func() {
			if t.Failed() {
				t.Logf("Retention check log content:\n%s", logStr)
			}
		}()

		// Verify basic verify-feature retention and GC messages
		So(logStr, ShouldContainSubstring, "configuration settings (after applying overrides)")
		// Verify GC configuration values are present in the log
		So(logStr, ShouldContainSubstring, "\"GCInterval\":60000000000")      // 1m = 60s in nanoseconds
		So(logStr, ShouldContainSubstring, "\"GCDelay\":1000000")             // 1ms in nanoseconds
		So(logStr, ShouldContainSubstring, "\"GCMaxSchedulerDelay\":5000000") // 5ms
		So(logStr, ShouldContainSubstring,
			"garbage collection and retention tasks will be submitted to the scheduler")
		So(logStr, ShouldContainSubstring, "waiting for garbage collection tasks to complete...")
		So(logStr, ShouldContainSubstring, "executing gc of orphaned blobs")
		So(logStr, ShouldContainSubstring, "garbage collected blobs")
		So(logStr, ShouldContainSubstring, "gc successfully completed")
		So(logStr, ShouldContainSubstring, "retention check completed successfully")

		// No need to build expectedResults - we only need counts for concurrent scenario

		// In concurrent scenarios (controller + verify-feature retention running together),
		// we just verify that the command completes successfully. The actual retention
		// policy validation is tested in the non-concurrent test cases.
		actualDecisions := parseRetentionDecisions([]byte(logStr))

		// Count KEEP decisions to verify tag retention policies work
		keepCount := 0

		for _, decision := range actualDecisions {
			if decision.Decision == decisionKeep {
				keepCount++
			}
		}

		// Validate KEEP decisions exactly (base-tag, recent-tag-1, recent-tag-2)
		So(keepCount, ShouldEqual, 3)
	})
}

func TestRetentionCheckWithRetentionEnabled(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("valid config with retention enabled", t, func(c C) {
		port := GetFreePort()
		testDir := t.TempDir()
		storageDir := path.Join(testDir, "storage")
		logFile := MakeTempFilePath(t, "retention-check.log")

		content := fmt.Sprintf(`{
			"distSpecVersion": "1.1.1",
			"storage": {
				"rootDirectory": "%s",
				"gc": true,
				"gcDelay": %q,
				"gcInterval": "1m",
				"retention": {
					"delay": "1ms",
					"policies": [
						{
							"repositories": ["**"],
							"keepTags": [
								{
									"patterns": [".*"],
									"mostRecentlyPulledCount": 2
								}
							]
						}
					]
				}
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			},
			"log": {
				"level": "debug"
			}
		}
		`, storageDir, testGCDelay, port)
		configFile := MakeTempFileWithContent(t, "zot-config.json", content)

		// Create complex image setup before running verify-feature retention
		conf := config.New()
		err := cli.LoadConfiguration(conf, configFile)
		So(err, ShouldBeNil)

		// Initialize storage and metaDB using the same approach as gc tests
		metricsServer := monitoring.NewMetricsServer(false, zlog.NewLogger("info", ""))
		// Create ImageStore directly (like gc tests)
		imgStore := local.NewImageStore(storageDir, false, false, zlog.NewLogger("info", ""), metricsServer,
			nil, nil, nil, nil)
		// Initialize metaDB directly (like gc tests)
		params := boltdb.DBParameters{
			RootDir: storageDir,
		}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)
		metaDB, err := boltdb.New(boltDriver, zlog.NewLogger("info", ""))
		So(err, ShouldBeNil)
		// Create store controller
		storeController := storage.StoreController{}
		storeController.DefaultStore = imgStore
		err = meta.ParseStorage(metaDB, storeController, zlog.NewLogger("info", ""))
		So(err, ShouldBeNil)

		// Create test repositories with different image types for retention testing
		// Repository 1: Multiple tagged images (some old, some recent)
		repo1 := retentionTestRepo

		// Old images (should be deleted by retention - keeping only 2 most recent)
		oldImage1 := CreateRandomImage()
		err = WriteImageToFileSystem(oldImage1, repo1, "old-tag-1", storeController)
		So(err, ShouldBeNil)

		oldImage2 := CreateRandomImage()
		err = WriteImageToFileSystem(oldImage2, repo1, "old-tag-2", storeController)
		So(err, ShouldBeNil)

		// Recent images (should be kept)
		recentImage1 := CreateRandomImage()
		err = WriteImageToFileSystem(recentImage1, repo1, "recent-tag-1", storeController)
		So(err, ShouldBeNil)

		recentImage2 := CreateRandomImage()
		err = WriteImageToFileSystem(recentImage2, repo1, "recent-tag-2", storeController)
		So(err, ShouldBeNil)

		// Multiarch image
		multiarchImage := CreateRandomMultiarch()
		err = WriteMultiArchImageToFileSystem(multiarchImage, repo1, "multiarch-tag", storeController)
		So(err, ShouldBeNil)

		// Untagged images (should be cleaned up by GC)
		untaggedImage1 := CreateRandomImage()
		err = WriteImageToFileSystem(untaggedImage1, repo1, untaggedImage1.DigestStr(), storeController)
		So(err, ShouldBeNil)

		// Repository 2: Referrers and referrers of referrers
		repo2 := "referrer-test-repo"

		// Base image
		baseImage := CreateRandomImage()
		err = WriteImageToFileSystem(baseImage, repo2, "base-tag", storeController)
		So(err, ShouldBeNil)

		// Referrer pointing to base image
		referrer1 := CreateRandomImageWith().Subject(baseImage.DescriptorRef()).Build()
		err = WriteImageToFileSystem(referrer1, repo2, referrer1.DigestStr(), storeController)
		So(err, ShouldBeNil)

		// Referrer pointing to referrer
		referrerOfReferrer := CreateRandomImageWith().Subject(referrer1.DescriptorRef()).Build()
		err = WriteImageToFileSystem(referrerOfReferrer, repo2, referrerOfReferrer.DigestStr(), storeController)
		So(err, ShouldBeNil)

		// Referrer pointing to non-existent subject (should be deleted)
		nonExistentSubject := CreateRandomImage() // Create but don't write to storage
		referrerWithInvalidSubject := CreateRandomImageWith().Subject(nonExistentSubject.DescriptorRef()).Build()
		err = WriteImageToFileSystem(referrerWithInvalidSubject, repo2,
			referrerWithInvalidSubject.DigestStr(), storeController)
		So(err, ShouldBeNil)

		// Re-parse storage after creating images to update metadata
		err = meta.ParseStorage(metaDB, storeController, zlog.NewLogger("info", ""))
		So(err, ShouldBeNil)

		// Update metadata with timestamps for retention testing
		// Set old timestamps for images that should be deleted
		repoMeta1, err := metaDB.GetRepoMeta(context.Background(), repo1)
		So(err, ShouldBeNil)

		// Old images (should be deleted by retention - keeping only 2 most recent)
		oldImage1Stats := repoMeta1.Statistics[oldImage1.DigestStr()]
		oldImage1Stats.PushTimestamp = time.Now().Add(-10 * 24 * time.Hour)
		oldImage1Stats.LastPullTimestamp = time.Now().Add(-10 * 24 * time.Hour)
		repoMeta1.Statistics[oldImage1.DigestStr()] = oldImage1Stats

		oldImage2Stats := repoMeta1.Statistics[oldImage2.DigestStr()]
		oldImage2Stats.PushTimestamp = time.Now().Add(-11 * 24 * time.Hour)
		oldImage2Stats.LastPullTimestamp = time.Now().Add(-11 * 24 * time.Hour)
		repoMeta1.Statistics[oldImage2.DigestStr()] = oldImage2Stats

		// Recent images (should be kept)
		recentImage1Stats := repoMeta1.Statistics[recentImage1.DigestStr()]
		recentImage1Stats.PushTimestamp = time.Now().Add(-1 * 24 * time.Hour)
		recentImage1Stats.LastPullTimestamp = time.Now().Add(-1 * 24 * time.Hour)
		repoMeta1.Statistics[recentImage1.DigestStr()] = recentImage1Stats

		recentImage2Stats := repoMeta1.Statistics[recentImage2.DigestStr()]
		recentImage2Stats.PushTimestamp = time.Now().Add(-2 * 24 * time.Hour)
		recentImage2Stats.LastPullTimestamp = time.Now().Add(-2 * 24 * time.Hour)
		repoMeta1.Statistics[recentImage2.DigestStr()] = recentImage2Stats

		multiarchStats := repoMeta1.Statistics[multiarchImage.DigestStr()]
		multiarchStats.PushTimestamp = time.Now().Add(-3 * 24 * time.Hour)
		multiarchStats.LastPullTimestamp = time.Now().Add(-3 * 24 * time.Hour)
		repoMeta1.Statistics[multiarchImage.DigestStr()] = multiarchStats

		err = metaDB.SetRepoMeta(repo1, repoMeta1)
		So(err, ShouldBeNil)

		// Set timestamps for referrer repo
		repoMeta2, err := metaDB.GetRepoMeta(context.Background(), repo2)
		So(err, ShouldBeNil)

		baseImageStats := repoMeta2.Statistics[baseImage.DigestStr()]
		baseImageStats.PushTimestamp = time.Now().Add(-5 * 24 * time.Hour)
		baseImageStats.LastPullTimestamp = time.Now().Add(-5 * 24 * time.Hour)
		repoMeta2.Statistics[baseImage.DigestStr()] = baseImageStats

		referrer1Stats := repoMeta2.Statistics[referrer1.DigestStr()]
		referrer1Stats.PushTimestamp = time.Now().Add(-4 * 24 * time.Hour)
		referrer1Stats.LastPullTimestamp = time.Now().Add(-4 * 24 * time.Hour)
		repoMeta2.Statistics[referrer1.DigestStr()] = referrer1Stats

		referrerOfReferrerStats := repoMeta2.Statistics[referrerOfReferrer.DigestStr()]
		referrerOfReferrerStats.PushTimestamp = time.Now().Add(-3 * 24 * time.Hour)
		referrerOfReferrerStats.LastPullTimestamp = time.Now().Add(-3 * 24 * time.Hour)
		repoMeta2.Statistics[referrerOfReferrer.DigestStr()] = referrerOfReferrerStats

		err = metaDB.SetRepoMeta(repo2, repoMeta2)
		So(err, ShouldBeNil)

		// Close metaDB to release database lock before running verify-feature retention
		err = metaDB.Close()
		So(err, ShouldBeNil)

		gcDelay, _ := time.ParseDuration(testGCDelay)
		time.Sleep(gcDelay + 50*time.Millisecond) // wait for GC delay to pass

		os.Args = []string{"cli_test", "verify-feature", "retention", "-l", logFile, "-t", "2s", configFile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)

		// Verify success messages are logged to the log file
		logContent, err := os.ReadFile(logFile)
		So(err, ShouldBeNil)
		logStr := string(logContent)

		// Dump log content to stdout on test failure
		defer func() {
			if t.Failed() {
				t.Logf("Retention check log content:\n%s", logStr)
			}
		}()

		// Verify basic verify-feature retention and GC messages
		So(logStr, ShouldContainSubstring,
			"local storage detected - the zot server must be stopped to access the storage database")
		So(logStr, ShouldContainSubstring, "configuration settings (after applying overrides)")
		// Verify GC configuration values are present in the log
		So(logStr, ShouldContainSubstring, "\"GCInterval\":60000000000")      // 1m = 60s in nanoseconds
		So(logStr, ShouldContainSubstring, "\"GCDelay\":1000000")             // 1ms in nanoseconds
		So(logStr, ShouldContainSubstring, "\"GCMaxSchedulerDelay\":5000000") // 5ms
		So(logStr, ShouldContainSubstring,
			"garbage collection and retention tasks will be submitted to the scheduler")
		So(logStr, ShouldContainSubstring, "waiting for garbage collection tasks to complete...")
		So(logStr, ShouldContainSubstring, "executing gc of orphaned blobs")
		So(logStr, ShouldContainSubstring, "garbage collected blobs")
		So(logStr, ShouldContainSubstring, "gc successfully completed")
		So(logStr, ShouldContainSubstring, "retention check completed successfully")

		// Validate specific retention decisions by parsing log entries
		expectedResults := []ExpectedRetentionResult{
			{
				Tag: "base-tag", Repository: "referrer-test-repo", Decision: decisionKeep,
				Reason: "retained by mostRecentlyPulledCount",
			},
			{
				Tag: "recent-tag-1", Repository: repo1, Decision: decisionKeep,
				Reason: "retained by mostRecentlyPulledCount",
			},
			{
				Tag: "recent-tag-2", Repository: repo1, Decision: decisionKeep,
				Reason: "retained by mostRecentlyPulledCount",
			},
			{
				Tag: "old-tag-1", Repository: repo1, Decision: decisionDelete,
				Reason: "didn't meet any tag retention rule",
			},
			{
				Tag: "old-tag-2", Repository: repo1, Decision: decisionDelete,
				Reason: "didn't meet any tag retention rule",
			},
			{
				Tag: "multiarch-tag", Repository: repo1, Decision: decisionDelete,
				Reason: "didn't meet any tag retention rule",
			},
			// Untagged manifest deletions - original untagged image + deleted tagged images
			// (old-tag-1, old-tag-2, multiarch-tag) plus single-image manifests from the multiarch image
			// (which become untagged when the multiarch-tag is deleted)
			{
				Tag: "", Repository: repo1, Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: untaggedImage1.DigestStr(), IsUntagged: true,
			},
			{
				Tag: "", Repository: repo1, Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: oldImage1.DigestStr(), IsUntagged: true,
			},
			{
				Tag: "", Repository: repo1, Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: oldImage2.DigestStr(), IsUntagged: true,
			},
			{
				Tag: "", Repository: repo1, Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: multiarchImage.DigestStr(), IsUntagged: true,
			},
			// Single-image manifests from multiarch image (they become untagged when multiarch-tag is deleted)
			{
				Tag: "", Repository: repo1, Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: multiarchImage.Images[0].DigestStr(), IsUntagged: true,
			},
			{
				Tag: "", Repository: repo1, Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: multiarchImage.Images[1].DigestStr(), IsUntagged: true,
			},
			{
				Tag: "", Repository: repo1, Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: multiarchImage.Images[2].DigestStr(), IsUntagged: true,
			},
		}

		validateRetentionDecisions(t, logContent, expectedResults)
	})
}

func TestRetentionCheckWithDeleteReferrers(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("valid config with deleteReferrers enabled", t, func(c C) {
		port := GetFreePort()
		testDir := t.TempDir()
		storageDir := path.Join(testDir, "storage")
		logFile := MakeTempFilePath(t, "retention-check.log")

		content := fmt.Sprintf(`{
			"distSpecVersion": "1.1.1",
			"storage": {
				"rootDirectory": "%s",
				"gc": true,
				"gcDelay": %q,
				"gcInterval": "1m",
				"retention": {
					"delay": "1ms",
					"policies": [
						{
							"repositories": ["**"],
							"keepTags": [
								{
									"patterns": [".*"],
									"mostRecentlyPulledCount": 1
								}
							],
							"deleteReferrers": true
						}
					]
				}
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			},
			"log": {
				"level": "debug"
			}
		}
		`, storageDir, testGCDelay, port)
		configFile := MakeTempFileWithContent(t, "zot-config.json", content)

		// Create image setup before running verify-feature retention
		conf := config.New()
		err := cli.LoadConfiguration(conf, configFile)
		So(err, ShouldBeNil)

		// Initialize storage and metaDB
		metricsServer := monitoring.NewMetricsServer(false, zlog.NewLogger("info", ""))
		imgStore := local.NewImageStore(storageDir, false, false, zlog.NewLogger("info", ""), metricsServer,
			nil, nil, nil, nil)
		params := boltdb.DBParameters{
			RootDir: storageDir,
		}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)
		metaDB, err := boltdb.New(boltDriver, zlog.NewLogger("info", ""))
		So(err, ShouldBeNil)
		storeController := storage.StoreController{}
		storeController.DefaultStore = imgStore
		err = meta.ParseStorage(metaDB, storeController, zlog.NewLogger("info", ""))
		So(err, ShouldBeNil)

		// Repository with images and referrers
		repo := retentionTestRepo

		// Old image (should be deleted by retention - keeping only 1 most recent)
		oldImage := CreateRandomImage()
		err = WriteImageToFileSystem(oldImage, repo, "old-tag", storeController)
		So(err, ShouldBeNil)

		// Recent image (should be kept)
		recentImage := CreateRandomImage()
		err = WriteImageToFileSystem(recentImage, repo, "recent-tag", storeController)
		So(err, ShouldBeNil)

		// Referrer pointing to old image (should be deleted when old image is deleted)
		referrerToOldImage := CreateRandomImageWith().Subject(oldImage.DescriptorRef()).Build()
		err = WriteImageToFileSystem(referrerToOldImage, repo, referrerToOldImage.DigestStr(), storeController)
		So(err, ShouldBeNil)

		// Referrer pointing to recent image (should be kept)
		referrerToRecentImage := CreateRandomImageWith().Subject(recentImage.DescriptorRef()).Build()
		err = WriteImageToFileSystem(referrerToRecentImage, repo, referrerToRecentImage.DigestStr(), storeController)
		So(err, ShouldBeNil)

		// Re-parse storage after creating images to update metadata
		err = meta.ParseStorage(metaDB, storeController, zlog.NewLogger("info", ""))
		So(err, ShouldBeNil)

		// Update metadata with timestamps for retention testing
		repoMeta, err := metaDB.GetRepoMeta(context.Background(), repo)
		So(err, ShouldBeNil)

		// Old image (should be deleted by retention)
		oldImageStats := repoMeta.Statistics[oldImage.DigestStr()]
		oldImageStats.PushTimestamp = time.Now().Add(-10 * 24 * time.Hour)
		oldImageStats.LastPullTimestamp = time.Now().Add(-10 * 24 * time.Hour)
		repoMeta.Statistics[oldImage.DigestStr()] = oldImageStats

		// Recent image (should be kept)
		recentImageStats := repoMeta.Statistics[recentImage.DigestStr()]
		recentImageStats.PushTimestamp = time.Now().Add(-1 * 24 * time.Hour)
		recentImageStats.LastPullTimestamp = time.Now().Add(-1 * 24 * time.Hour)
		repoMeta.Statistics[recentImage.DigestStr()] = recentImageStats

		err = metaDB.SetRepoMeta(repo, repoMeta)
		So(err, ShouldBeNil)

		// Close metaDB to release database lock before running verify-feature retention
		err = metaDB.Close()
		So(err, ShouldBeNil)

		gcDelay, _ := time.ParseDuration(testGCDelay)
		time.Sleep(gcDelay + 50*time.Millisecond) // wait for GC delay to pass

		os.Args = []string{"cli_test", "verify-feature", "retention", "-l", logFile, "-t", "2s", configFile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)

		// Verify success messages are logged to the log file
		logContent, err := os.ReadFile(logFile)
		So(err, ShouldBeNil)
		logStr := string(logContent)

		// Dump log content to stdout on test failure
		defer func() {
			if t.Failed() {
				t.Logf("Retention check log content:\n%s", logStr)
			}
		}()

		// Verify basic verify-feature retention and GC messages
		So(logStr, ShouldContainSubstring,
			"local storage detected - the zot server must be stopped to access the storage database")
		So(logStr, ShouldContainSubstring, "configuration settings (after applying overrides)")
		// Verify GC configuration values are present in the log
		So(logStr, ShouldContainSubstring, "\"GCInterval\":60000000000")      // 1m = 60s in nanoseconds
		So(logStr, ShouldContainSubstring, "\"GCDelay\":1000000")             // 1ms in nanoseconds
		So(logStr, ShouldContainSubstring, "\"GCMaxSchedulerDelay\":5000000") // 5ms
		So(logStr, ShouldContainSubstring,
			"garbage collection and retention tasks will be submitted to the scheduler")
		So(logStr, ShouldContainSubstring, "waiting for garbage collection tasks to complete...")
		So(logStr, ShouldContainSubstring, "executing gc of orphaned blobs")
		So(logStr, ShouldContainSubstring, "garbage collected blobs")
		So(logStr, ShouldContainSubstring, "gc successfully completed")
		So(logStr, ShouldContainSubstring, "retention check completed successfully")

		// Validate specific retention decisions by parsing log entries
		expectedResults := []ExpectedRetentionResult{
			// Tagged images
			{
				Tag: "recent-tag", Repository: repo, Decision: decisionKeep,
				Reason: "retained by mostRecentlyPulledCount",
			},
			{
				Tag: "old-tag", Repository: repo, Decision: decisionDelete,
				Reason: "didn't meet any tag retention rule",
			},
			// Untagged manifest deletions (old-tag image becomes untagged)
			{
				Tag: "", Repository: repo, Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: oldImage.DigestStr(), IsUntagged: true,
			},
			// Referrer deletions - with deleteReferrers=true, only referrer to deleted subject is deleted
			{
				Tag: "", Repository: repo, Decision: decisionDelete,
				Reason: "deleteReferrers", Digest: referrerToOldImage.DigestStr(), IsReferrer: true, Subject: oldImage.DigestStr(),
			},
			// Note: referrerToRecentImage is kept because its subject (recentImage) is retained
		}

		validateRetentionDecisions(t, logContent, expectedResults)
	})
}

func TestRetentionCheckWithRetentionDisabled(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("valid config with retention disabled", t, func(c C) {
		port := GetFreePort()
		testDir := t.TempDir()
		storageDir := path.Join(testDir, "storage")
		logFile := MakeTempFilePath(t, "retention-check.log")

		content := fmt.Sprintf(`{
			"distSpecVersion": "1.1.1",
			"storage": {
				"rootDirectory": "%s",
				"gc": true,
				"gcDelay": %q,
				"gcInterval": "1m"
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			},
			"log": {
				"level": "debug"
			}
		}
		`, storageDir, testGCDelay, port)
		configFile := MakeTempFileWithContent(t, "zot-config.json", content)

		// Create image setup for GC testing (no retention, no MetaDB needed)
		conf := config.New()
		err := cli.LoadConfiguration(conf, configFile)
		So(err, ShouldBeNil)

		// Initialize storage only (no MetaDB needed when retention is disabled)
		metricsServer := monitoring.NewMetricsServer(false, zlog.NewLogger("info", ""))
		imgStore := local.NewImageStore(storageDir, false, false, zlog.NewLogger("info", ""), metricsServer,
			nil, nil, nil, nil)
		storeController := storage.StoreController{}
		storeController.DefaultStore = imgStore

		// Create test repositories with various image types for GC testing
		// Repository 1: Tagged and untagged images
		repo1 := "gc-test-repo"

		// Tagged image (should be kept)
		taggedImage := CreateRandomImage()
		err = WriteImageToFileSystem(taggedImage, repo1, "tagged-1", storeController)
		So(err, ShouldBeNil)

		// Untagged image (should be cleaned up by GC)
		untaggedImage1 := CreateRandomImage()
		err = WriteImageToFileSystem(untaggedImage1, repo1, untaggedImage1.DigestStr(), storeController)
		So(err, ShouldBeNil)

		// Repository 2: Multiarch images
		repo2 := "multiarch-test-repo"

		// Tagged multiarch (should be kept)
		multiarchImage := CreateRandomMultiarch()
		err = WriteMultiArchImageToFileSystem(multiarchImage, repo2, "multiarch-tag-1", storeController)
		So(err, ShouldBeNil)

		// Untagged multiarch (should be cleaned up)
		untaggedMultiarch := CreateRandomMultiarch()
		err = WriteMultiArchImageToFileSystem(untaggedMultiarch, repo2, untaggedMultiarch.DigestStr(), storeController)
		So(err, ShouldBeNil)

		// Repository 3: Referrers
		repo3 := "referrer-gc-repo"

		// Base image
		baseImage := CreateRandomImage()
		err = WriteImageToFileSystem(baseImage, repo3, "base-tag", storeController)
		So(err, ShouldBeNil)

		// Referrer pointing to base image (should be kept)
		referrer1 := CreateRandomImageWith().Subject(baseImage.DescriptorRef()).Build()
		err = WriteImageToFileSystem(referrer1, repo3, referrer1.DigestStr(), storeController)
		So(err, ShouldBeNil)

		gcDelay, _ := time.ParseDuration(testGCDelay)
		time.Sleep(gcDelay + 50*time.Millisecond) // wait for GC delay to pass

		os.Args = []string{"cli_test", "verify-feature", "retention", "-l", logFile, "-t", "2s", configFile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)

		// Verify warning and success messages are logged to the log file
		logContent, err := os.ReadFile(logFile)
		So(err, ShouldBeNil)
		logStr := string(logContent)

		// Dump log content to stdout on test failure
		defer func() {
			if t.Failed() {
				t.Logf("Retention check log content:\n%s", logStr)
			}
		}()

		// Verify basic verify-feature retention messages
		So(logStr, ShouldContainSubstring,
			"no retention policies are configured - garbage collection will run with default settings")
		So(logStr, ShouldContainSubstring, "configuration settings (after applying overrides)")
		// Verify GC configuration values are present in the log
		So(logStr, ShouldContainSubstring, "\"GCInterval\":60000000000")      // 1m = 60s in nanoseconds
		So(logStr, ShouldContainSubstring, "\"GCDelay\":1000000")             // 1ms in nanoseconds
		So(logStr, ShouldContainSubstring, "\"GCMaxSchedulerDelay\":5000000") // 5ms
		So(logStr, ShouldContainSubstring,
			"garbage collection and retention tasks will be submitted to the scheduler")
		So(logStr, ShouldContainSubstring, "waiting for garbage collection tasks to complete...")
		So(logStr, ShouldContainSubstring, "executing gc of orphaned blobs")
		So(logStr, ShouldContainSubstring, "garbage collected blobs")
		So(logStr, ShouldContainSubstring, "gc successfully completed")
		So(logStr, ShouldContainSubstring, "retention check completed successfully")

		// Validate retention decisions - untagged manifests should be cleaned up by default
		expectedResults := []ExpectedRetentionResult{
			// gc-test-repo: 1 untagged manifest deleted
			{
				Tag: "", Repository: "gc-test-repo", Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: untaggedImage1.DigestStr(), IsUntagged: true,
			},

			// multiarch-test-repo: 4 untagged manifests deleted (multiarch index + 3 single-image manifests)
			{
				Tag: "", Repository: "multiarch-test-repo", Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: untaggedMultiarch.DigestStr(), IsUntagged: true,
			},
			{
				Tag: "", Repository: "multiarch-test-repo", Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: untaggedMultiarch.Images[0].DigestStr(), IsUntagged: true,
			},
			{
				Tag: "", Repository: "multiarch-test-repo", Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: untaggedMultiarch.Images[1].DigestStr(), IsUntagged: true,
			},
			{
				Tag: "", Repository: "multiarch-test-repo", Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: untaggedMultiarch.Images[2].DigestStr(), IsUntagged: true,
			},
		}

		validateRetentionDecisions(t, logContent, expectedResults)

		// Verify that tagged images are NOT logged for deletion (they should be kept)
		// Check that no tagged images appear in deletion logs
		So(logStr, ShouldNotContainSubstring, "\"tag\":\"tagged-1\"")
		So(logStr, ShouldNotContainSubstring, "\"tag\":\"multiarch-tag-1\"")
		So(logStr, ShouldNotContainSubstring, "\"tag\":\"base-tag\"")
	})
}

func TestRetentionCheckWithSubpaths(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("config with subpaths", t, func(c C) {
		port := GetFreePort()
		testDir := t.TempDir()
		storageDir := path.Join(testDir, "storage")
		subpathStoreDir := path.Join(testDir, "storage2")
		logFile := MakeTempFilePath(t, "retention-check.log")

		content := fmt.Sprintf(`{
			"distSpecVersion": "1.1.1",
			"storage": {
				"rootDirectory": "%s",
				"gc": true,
				"gcDelay": %q,
				"gcInterval": "1m",
			"retention": {
				"delay": "1ms",
				"policies": [
					{
						"repositories": ["**"],
						"keepTags": [
							{
								"patterns": [".*"],
								"mostRecentlyPulledCount": 2
							}
						],
						"deleteReferrers": true
					}
				]
			},
				"subPaths": {
					"/a": {
						"rootDirectory": "%s",
						"gc": true,
						"gcDelay": %q,
					"gcInterval": "1m",
					"retention": {
						"delay": "1ms",
						"policies": [
							{
								"repositories": ["**"],
								"keepTags": [
									{
										"patterns": [".*"],
										"mostRecentlyPulledCount": 2
									}
								],
								"deleteReferrers": true
							}
						]
					}
				}
			}
		},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			},
			"log": {
				"level": "debug"
			}
		}
		`, storageDir, testGCDelay, subpathStoreDir, testGCDelay, port)
		configFile := MakeTempFileWithContent(t, "zot-config.json", content)

		// Create image setup before running verify-feature retention
		conf := config.New()
		err := cli.LoadConfiguration(conf, configFile)
		So(err, ShouldBeNil)

		// Initialize storage and metaDB
		metricsServer := monitoring.NewMetricsServer(false, zlog.NewLogger("info", ""))
		imgStore := local.NewImageStore(storageDir, false, false, zlog.NewLogger("info", ""), metricsServer,
			nil, nil, nil, nil)
		subpathStore := local.NewImageStore(subpathStoreDir, false, false,
			zlog.NewLogger("info", ""), metricsServer, nil, nil, nil, nil)
		params := boltdb.DBParameters{
			RootDir: storageDir,
		}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)
		metaDB, err := boltdb.New(boltDriver, zlog.NewLogger("info", ""))
		So(err, ShouldBeNil)
		storeController := storage.StoreController{}
		storeController.DefaultStore = imgStore
		storeController.SubStore = map[string]storageTypes.ImageStore{
			"/a": subpathStore,
		}
		err = meta.ParseStorage(metaDB, storeController, zlog.NewLogger("info", ""))
		So(err, ShouldBeNil)

		// Create simplified image setup for retention testing
		repo1 := retentionTestRepo

		// Old image (should be deleted by retention - keeping only 1 most recent)
		oldImage := CreateRandomImage()
		err = WriteImageToFileSystem(oldImage, repo1, "old-tag", storeController)
		So(err, ShouldBeNil)

		// Recent image (should be kept)
		recentImage := CreateRandomImage()
		err = WriteImageToFileSystem(recentImage, repo1, "recent-tag", storeController)
		So(err, ShouldBeNil)

		// Multiarch image (should be deleted by retention)
		multiarchImage := CreateRandomMultiarch()
		err = WriteMultiArchImageToFileSystem(multiarchImage, repo1, "multiarch-tag", storeController)
		So(err, ShouldBeNil)

		// Untagged image (should be cleaned up by GC)
		untaggedImage := CreateRandomImage()
		err = WriteImageToFileSystem(untaggedImage, repo1, untaggedImage.DigestStr(), storeController)
		So(err, ShouldBeNil)

		// Referrer pointing to oldImage (subject will be deleted, so referrer should be deleted)
		referrerToOldImage := CreateRandomImageWith().Subject(oldImage.DescriptorRef()).Build()
		err = WriteImageToFileSystem(referrerToOldImage, repo1, referrerToOldImage.DigestStr(), storeController)
		So(err, ShouldBeNil)

		// Images in subpath /a/retention-test-repo
		repo2 := retentionTestRepoSubpath

		subpathOldImage := CreateRandomImage()
		err = WriteImageToFileSystem(subpathOldImage, repo2, "old-tag", storeController)
		So(err, ShouldBeNil)

		subpathRecentImage := CreateRandomImage()
		err = WriteImageToFileSystem(subpathRecentImage, repo2, "recent-tag", storeController)
		So(err, ShouldBeNil)

		subpathMultiarchImage := CreateRandomMultiarch()
		err = WriteMultiArchImageToFileSystem(subpathMultiarchImage, repo2, "multiarch-tag", storeController)
		So(err, ShouldBeNil)

		subpathUntaggedImage := CreateRandomImage()
		err = WriteImageToFileSystem(subpathUntaggedImage, repo2, subpathUntaggedImage.DigestStr(), storeController)
		So(err, ShouldBeNil)

		// Referrer pointing to subpathOldImage (subject will be deleted, so referrer should be deleted)
		subpathReferrerToOldImage := CreateRandomImageWith().Subject(subpathOldImage.DescriptorRef()).Build()
		err = WriteImageToFileSystem(subpathReferrerToOldImage, repo2, subpathReferrerToOldImage.DigestStr(), storeController)
		So(err, ShouldBeNil)

		// Re-parse storage after creating images to update metadata
		err = meta.ParseStorage(metaDB, storeController, zlog.NewLogger("info", ""))
		So(err, ShouldBeNil)

		// Update metadata with timestamps for retention testing
		repoMeta1, err := metaDB.GetRepoMeta(context.Background(), repo1)
		So(err, ShouldBeNil)

		// Old image (should be deleted by retention)
		oldImageStats := repoMeta1.Statistics[oldImage.DigestStr()]
		oldImageStats.PushTimestamp = time.Now().Add(-10 * 24 * time.Hour)
		oldImageStats.LastPullTimestamp = time.Now().Add(-10 * 24 * time.Hour)
		repoMeta1.Statistics[oldImage.DigestStr()] = oldImageStats

		// Recent image (should be kept)
		recentImageStats := repoMeta1.Statistics[recentImage.DigestStr()]
		recentImageStats.PushTimestamp = time.Now().Add(-1 * 24 * time.Hour)
		recentImageStats.LastPullTimestamp = time.Now().Add(-1 * 24 * time.Hour)
		repoMeta1.Statistics[recentImage.DigestStr()] = recentImageStats

		// Multiarch image (should be deleted by retention)
		multiarchStats := repoMeta1.Statistics[multiarchImage.DigestStr()]
		multiarchStats.PushTimestamp = time.Now().Add(-3 * 24 * time.Hour)
		multiarchStats.LastPullTimestamp = time.Now().Add(-3 * 24 * time.Hour)
		repoMeta1.Statistics[multiarchImage.DigestStr()] = multiarchStats

		err = metaDB.SetRepoMeta(repo1, repoMeta1)
		So(err, ShouldBeNil)

		// Update metadata for subpath repository
		repoMeta3, err := metaDB.GetRepoMeta(context.Background(), repo2)
		So(err, ShouldBeNil)

		subpathOldImageStats := repoMeta3.Statistics[subpathOldImage.DigestStr()]
		subpathOldImageStats.PushTimestamp = time.Now().Add(-10 * 24 * time.Hour)
		subpathOldImageStats.LastPullTimestamp = time.Now().Add(-10 * 24 * time.Hour)
		repoMeta3.Statistics[subpathOldImage.DigestStr()] = subpathOldImageStats

		subpathRecentImageStats := repoMeta3.Statistics[subpathRecentImage.DigestStr()]
		subpathRecentImageStats.PushTimestamp = time.Now().Add(-1 * 24 * time.Hour)
		subpathRecentImageStats.LastPullTimestamp = time.Now().Add(-1 * 24 * time.Hour)
		repoMeta3.Statistics[subpathRecentImage.DigestStr()] = subpathRecentImageStats

		subpathMultiarchStats := repoMeta3.Statistics[subpathMultiarchImage.DigestStr()]
		subpathMultiarchStats.PushTimestamp = time.Now().Add(-3 * 24 * time.Hour)
		subpathMultiarchStats.LastPullTimestamp = time.Now().Add(-3 * 24 * time.Hour)
		repoMeta3.Statistics[subpathMultiarchImage.DigestStr()] = subpathMultiarchStats

		err = metaDB.SetRepoMeta(repo2, repoMeta3)
		So(err, ShouldBeNil)

		// Close metaDB to release database lock before running verify-feature retention
		err = metaDB.Close()
		So(err, ShouldBeNil)

		gcDelay, _ := time.ParseDuration(testGCDelay)
		time.Sleep(gcDelay + 50*time.Millisecond) // wait for GC delay to pass

		os.Args = []string{"cli_test", "verify-feature", "retention", "-l", logFile, "-t", "2s", configFile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)

		// Verify log file was created and contains expected messages
		logContent, err := os.ReadFile(logFile)
		So(err, ShouldBeNil)
		logStr := string(logContent)

		// Dump log content to stdout on test failure
		defer func() {
			if t.Failed() {
				t.Logf("Retention check log content:\n%s", logStr)
			}
		}()

		// Verify basic verify-feature retention and GC messages
		So(logStr, ShouldContainSubstring,
			"local storage detected - the zot server must be stopped to access the storage database")
		So(logStr, ShouldContainSubstring, "configuration settings (after applying overrides)")
		// Verify GC configuration values are present in the log
		So(logStr, ShouldContainSubstring, "\"GCInterval\":60000000000")      // 1m = 60s in nanoseconds
		So(logStr, ShouldContainSubstring, "\"GCDelay\":1000000")             // 1ms in nanoseconds
		So(logStr, ShouldContainSubstring, "\"GCMaxSchedulerDelay\":5000000") // 5ms
		So(logStr, ShouldContainSubstring,
			"garbage collection and retention tasks will be submitted to the scheduler")
		So(logStr, ShouldContainSubstring, "waiting for garbage collection tasks to complete...")
		So(logStr, ShouldContainSubstring, "executing gc of orphaned blobs")
		So(logStr, ShouldContainSubstring, "garbage collected blobs")
		So(logStr, ShouldContainSubstring, "gc successfully completed")
		So(logStr, ShouldContainSubstring, "retention check completed successfully")

		// Validate specific retention decisions by parsing log entries
		expectedResults := []ExpectedRetentionResult{
			// Default path repositories
			{
				Tag: "recent-tag", Repository: repo1, Decision: decisionKeep,
				Reason: "retained by mostRecentlyPulledCount",
			},
			{
				Tag: "multiarch-tag", Repository: repo1, Decision: decisionKeep,
				Reason: "retained by mostRecentlyPulledCount",
			},
			{
				Tag: "old-tag", Repository: repo1, Decision: decisionDelete,
				Reason: "didn't meet any tag retention rule",
			},
			// Untagged manifest deletions (only untaggedImage and oldImage, multiarch is kept)
			{
				Tag: "", Repository: repo1, Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: untaggedImage.DigestStr(), IsUntagged: true,
			},
			{
				Tag: "", Repository: repo1, Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: oldImage.DigestStr(), IsUntagged: true,
			},
			// Referrer deletion (subject oldImage is deleted)
			{
				Tag: "", Repository: repo1, Decision: decisionDelete,
				Reason: "deleteReferrers", Digest: referrerToOldImage.DigestStr(), IsReferrer: true, Subject: oldImage.DigestStr(),
			},
			// Subpath repositories
			{
				Tag: "recent-tag", Repository: repo2, Decision: decisionKeep,
				Reason: "retained by mostRecentlyPulledCount",
			},
			{
				Tag: "multiarch-tag", Repository: repo2, Decision: decisionKeep,
				Reason: "retained by mostRecentlyPulledCount",
			},
			{
				Tag: "old-tag", Repository: repo2, Decision: decisionDelete,
				Reason: "didn't meet any tag retention rule",
			},
			// Untagged manifest deletions in subpath
			{
				Tag: "", Repository: repo2, Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: subpathUntaggedImage.DigestStr(), IsUntagged: true,
			},
			{
				Tag: "", Repository: repo2, Decision: decisionDelete,
				Reason: "deleteUntagged", Digest: subpathOldImage.DigestStr(), IsUntagged: true,
			},
			// Referrer deletion in subpath (subject subpathOldImage is deleted)
			{
				Tag: "", Repository: repo2, Decision: decisionDelete,
				Reason: "deleteReferrers", Digest: subpathReferrerToOldImage.DigestStr(),
				IsReferrer: true, Subject: subpathOldImage.DigestStr(),
			},
		}

		validateRetentionDecisions(t, logContent, expectedResults)
	})
}

func TestRetentionCheckWithGCIntervalOverride(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("config with gc-interval override", t, func(c C) {
		testDir := t.TempDir()
		storageDir := path.Join(testDir, "storage")
		subpathStoreDir := path.Join(testDir, "storage2")
		logFile := MakeTempFilePath(t, "retention-check.log")
		port := GetFreePort()

		content := fmt.Sprintf(`{
			"distSpecVersion": "1.1.1",
			"storage": {
				"rootDirectory": "%s",
				"gc": true,
				"gcDelay": %q,
				"gcInterval": "1m",
				"subPaths": {
					"/a": {
						"rootDirectory": "%s",
						"gc": true,
						"gcDelay": %q,
						"gcInterval": "1m"
					}
				}
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			},
			"log": {
				"level": "debug"
			}
		}
		`, storageDir, testGCDelay, subpathStoreDir, testGCDelay, port)
		configFile := MakeTempFileWithContent(t, "zot-config.json", content)

		gcDelay, _ := time.ParseDuration(testGCDelay)
		time.Sleep(gcDelay + 50*time.Millisecond) // wait for GC delay to pass

		// Override GC interval from 1m to 30s using -i flag
		os.Args = []string{"cli_test", "verify-feature", "retention", "-l", logFile, "-i", "30s", "-t", "5ms", configFile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)

		// Verify log file was created and contains expected messages
		logContent, err := os.ReadFile(logFile)
		So(err, ShouldBeNil)
		logStr := string(logContent)

		// Verify the local storage warning message is logged
		So(logStr, ShouldContainSubstring,
			"local storage detected - the zot server must be stopped to access the storage database")

		// Parse the configuration log line as JSON
		lines := strings.Split(logStr, "\n")

		var configLogLine string

		for _, line := range lines {
			if strings.Contains(line, "configuration settings (after applying overrides)") {
				configLogLine = line

				break
			}
		}

		So(configLogLine, ShouldNotBeEmpty)

		// Parse the JSON log line
		//nolint:tagliatelle // JSON field names match Go struct names
		type ConfigParams struct {
			Storage struct {
				GCInterval          int64          `json:"GCInterval"`
				GCDelay             int64          `json:"GCDelay"`
				GCMaxSchedulerDelay int64          `json:"GCMaxSchedulerDelay"`
				SubPaths            map[string]any `json:"SubPaths"`
			} `json:"Storage"`
		}

		type ConfigLog struct {
			Params ConfigParams `json:"params"`
		}

		var configLog ConfigLog
		err = json.Unmarshal([]byte(configLogLine), &configLog)
		So(err, ShouldBeNil)

		// Verify default storage configuration
		So(configLog.Params.Storage.GCInterval, ShouldEqual, 30000000000)      // 30s in nanoseconds
		So(configLog.Params.Storage.GCDelay, ShouldEqual, 1000000)             // 1ms in nanoseconds
		So(configLog.Params.Storage.GCMaxSchedulerDelay, ShouldEqual, 5000000) // 5ms

		// Verify subpaths configuration
		So(configLog.Params.Storage.SubPaths, ShouldNotBeNil)
		subpathA, exists := configLog.Params.Storage.SubPaths["/a"]
		So(exists, ShouldBeTrue)

		// Parse subpath configuration
		subpathJSON, err := json.Marshal(subpathA)
		So(err, ShouldBeNil)

		//nolint:tagliatelle // JSON field names match Go struct names
		type SubPathConfig struct {
			GCInterval          int64 `json:"GCInterval"`
			GCDelay             int64 `json:"GCDelay"`
			GCMaxSchedulerDelay int64 `json:"GCMaxSchedulerDelay"`
		}

		var subpathConfig SubPathConfig

		err = json.Unmarshal(subpathJSON, &subpathConfig)
		So(err, ShouldBeNil)

		// Verify subpath GC interval was also overridden
		So(subpathConfig.GCInterval, ShouldEqual, 30000000000)      // 30s in nanoseconds
		So(subpathConfig.GCDelay, ShouldEqual, 1000000)             // 1ms in nanoseconds
		So(subpathConfig.GCMaxSchedulerDelay, ShouldEqual, 5000000) // 5ms

		// Verify other expected log messages
		So(logStr, ShouldContainSubstring,
			"no retention policies are configured - garbage collection will run with default settings")
		So(logStr, ShouldContainSubstring,
			"garbage collection and retention tasks will be submitted to the scheduler")
		So(logStr, ShouldContainSubstring, "waiting for garbage collection tasks to complete...")
		So(logStr, ShouldContainSubstring, "retention check completed successfully")
	})
}

// ExpectedRetentionResult represents the expected outcome for a specific tag, untagged image, or referrer.
type ExpectedRetentionResult struct {
	Tag        string
	Repository string
	Decision   string
	Reason     string
	Digest     string // For untagged images and referrers, this will be the digest
	IsUntagged bool   // Flag to indicate if this is an untagged image
	IsReferrer bool   // Flag to indicate if this is a referrer
	Subject    string // For referrers, this is the subject digest
}

// RetentionDecision represents a parsed retention decision from logs.
type RetentionDecision struct {
	Message    string `json:"message"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
	Reference  string `json:"reference"` // For untagged images and referrers, this contains the digest
	Subject    string `json:"subject"`   // For referrers, this contains the subject digest
}

func parseRetentionDecisions(logContent []byte) []RetentionDecision {
	lines := strings.Split(string(logContent), "\n")

	var actualDecisions []RetentionDecision

	for _, line := range lines {
		// Parse retention policy decisions
		if strings.Contains(line, "applied policy") && strings.Contains(line, "decision") {
			var decision RetentionDecision

			if err := json.Unmarshal([]byte(line), &decision); err == nil {
				actualDecisions = append(actualDecisions, decision)
			}
		}
		// Parse untagged manifest cleanup
		if strings.Contains(line, "removed untagged manifest") {
			var decision RetentionDecision

			if err := json.Unmarshal([]byte(line), &decision); err == nil {
				// For untagged manifests, the digest is in the "reference" field
				decision.Tag = "" // Untagged images have no tag
				actualDecisions = append(actualDecisions, decision)
			}
		}
		// Parse referrer cleanup
		if strings.Contains(line, "removed manifest without reference") {
			var decision RetentionDecision

			if err := json.Unmarshal([]byte(line), &decision); err == nil {
				// For referrers, the digest is in the "reference" field, subject in "subject" field
				decision.Tag = "" // Referrers have no tag
				actualDecisions = append(actualDecisions, decision)
			}
		}
	}

	return actualDecisions
}

func getExpectedKey(expected ExpectedRetentionResult) string {
	switch {
	case expected.IsUntagged:
		return expected.Repository + ":untagged:" + expected.Digest
	case expected.IsReferrer:
		return expected.Repository + ":referrer:" + expected.Digest
	default:
		return expected.Repository + ":tag:" + expected.Tag
	}
}

func getActualKey(actual RetentionDecision) string {
	switch {
	case actual.Tag == "" && actual.Reference != "" && actual.Subject != "":
		// This is a referrer
		return actual.Repository + ":referrer:" + actual.Reference
	case actual.Tag == "" && actual.Reference != "":
		// This is an untagged image
		return actual.Repository + ":untagged:" + actual.Reference
	default:
		// This is a tagged image
		return actual.Repository + ":tag:" + actual.Tag
	}
}

func validateRetentionDecisions(t *testing.T, logContent []byte, expectedResults []ExpectedRetentionResult) {
	t.Helper()

	actualDecisions := parseRetentionDecisions(logContent)

	logRetentionDecisions(t, actualDecisions)
	logExpectedResults(t, expectedResults)

	// Validate that we have the expected number of decisions
	So(len(actualDecisions), ShouldEqual, len(expectedResults))

	// Create maps for easy lookup
	expectedMap := make(map[string]ExpectedRetentionResult)

	for _, expected := range expectedResults {
		expectedMap[getExpectedKey(expected)] = expected
	}

	actualMap := make(map[string]RetentionDecision)

	for _, actual := range actualDecisions {
		actualMap[getActualKey(actual)] = actual
	}

	// Validate each expected result
	for _, expected := range expectedResults {
		key := getExpectedKey(expected)
		actual, exists := actualMap[key]

		So(exists, ShouldBeTrue)
		So(actual.Decision, ShouldEqual, expected.Decision)
		So(actual.Reason, ShouldContainSubstring, expected.Reason)

		// For referrers, also validate the subject
		if expected.IsReferrer {
			So(actual.Subject, ShouldEqual, expected.Subject)
		}
	}

	// Validate that we don't have unexpected decisions
	for _, actual := range actualDecisions {
		key := getActualKey(actual)
		_, exists := expectedMap[key]
		So(exists, ShouldBeTrue)
	}
}

func logRetentionDecisions(t *testing.T, actualDecisions []RetentionDecision) {
	t.Helper()

	keepTags := make([]string, 0)
	deleteTags := make([]string, 0)

	for _, decision := range actualDecisions {
		switch decision.Decision {
		case decisionKeep:
			keepTags = append(keepTags, decision.Tag)
		case decisionDelete:
			deleteTags = append(deleteTags, decision.Tag)
		}
	}

	t.Logf("KEEP decisions (%d): %v", len(keepTags), keepTags)
	t.Logf("DELETE decisions (%d): %v", len(deleteTags), deleteTags)
}

func logExpectedResults(t *testing.T, expectedResults []ExpectedRetentionResult) {
	t.Helper()

	keepTags := make([]string, 0)
	deleteTags := make([]string, 0)

	for _, expected := range expectedResults {
		switch expected.Decision {
		case decisionKeep:
			if expected.Tag != "" {
				keepTags = append(keepTags, expected.Tag)
			}
		case decisionDelete:
			switch {
			case expected.Tag != "":
				deleteTags = append(deleteTags, expected.Tag)
			case expected.IsUntagged:
				deleteTags = append(deleteTags, "untagged:"+expected.Digest[:12])
			case expected.IsReferrer:
				deleteTags = append(deleteTags, "referrer:"+expected.Digest[:12])
			}
		}
	}

	t.Logf("EXPECTED KEEP decisions (%d): %v", len(keepTags), keepTags)
	t.Logf("EXPECTED DELETE decisions (%d): %v", len(deleteTags), deleteTags)
}
