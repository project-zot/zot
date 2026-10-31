package server

import (
	"os"
	"path"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

func writePushConfig(t *testing.T, body string) string {
	t.Helper()

	dir := t.TempDir()
	configPath := path.Join(dir, "config.json")

	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	return configPath
}

func TestSyncPushConfig(t *testing.T) {
	Convey("A push block parses into the registry config and validates", t, func() {
		configPath := writePushConfig(t, `{
			"distSpecVersion": "1.1.1",
			"storage": {"rootDirectory": "/tmp/zot-push-config-test"},
			"http": {"address": "127.0.0.1", "port": "8080"},
			"extensions": {
				"sync": {
					"enable": true,
					"registries": [{
						"pollInterval": "6h",
						"content": [{"prefix": "library/**"}],
						"push": {
							"enabled": true,
							"urls": ["https://zot.edge:5000"],
							"tlsVerify": false,
							"certDir": "/etc/zot/certs"
						}
					}]
				}
			}
		}`)

		conf := config.New()
		So(LoadConfiguration(conf, configPath), ShouldBeNil)

		push := conf.Extensions.Sync.Registries[0].Push
		So(push, ShouldNotBeNil)
		So(push.Enabled, ShouldNotBeNil)
		So(*push.Enabled, ShouldBeTrue)
		So(push.URLs, ShouldResemble, []string{"https://zot.edge:5000"})
		So(push.TLSVerify, ShouldNotBeNil)
		So(*push.TLSVerify, ShouldBeFalse)
		So(push.CertDir, ShouldEqual, "/etc/zot/certs")

		So(validateSync(conf, log.NewTestLogger()), ShouldBeNil)

		Convey("A push block without an allowlist is rejected", func() {
			deleteAllowlist := writePushConfig(t, `{
				"distSpecVersion": "1.1.1",
				"storage": {"rootDirectory": "/tmp/zot-push-config-test"},
				"http": {"address": "127.0.0.1", "port": "8080"},
				"extensions": {
					"sync": {
						"enable": true,
						"registries": [{
							"pollInterval": "6h",
							"push": {"enabled": true, "urls": ["https://zot.edge:5000"]}
						}]
					}
				}
			}`)

			// LoadConfiguration validates as well, so the rejection surfaces here.
			So(LoadConfiguration(config.New(), deleteAllowlist), ShouldNotBeNil)
		})

		Convey("A push block without destinations is rejected", func() {
			noURLs := writePushConfig(t, `{
				"distSpecVersion": "1.1.1",
				"storage": {"rootDirectory": "/tmp/zot-push-config-test"},
				"http": {"address": "127.0.0.1", "port": "8080"},
				"extensions": {
					"sync": {
						"enable": true,
						"registries": [{
							"pollInterval": "6h",
							"content": [{"prefix": "library/**"}],
							"push": {"enabled": true}
						}]
					}
				}
			}`)

			So(LoadConfiguration(config.New(), noURLs), ShouldNotBeNil)
		})

		Convey("Credentials in a destination url are rejected and not echoed", func() {
			withCreds := writePushConfig(t, `{
				"distSpecVersion": "1.1.1",
				"storage": {"rootDirectory": "/tmp/zot-push-config-test"},
				"http": {"address": "127.0.0.1", "port": "8080"},
				"extensions": {
					"sync": {
						"enable": true,
						"registries": [{
							"pollInterval": "6h",
							"content": [{"prefix": "library/**"}],
							"push": {"enabled": true, "urls": ["https://user:token@zot.edge:5000"]}
						}]
					}
				}
			}`)

			err := LoadConfiguration(config.New(), withCreds)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "must not carry credentials")
			So(strings.Contains(err.Error(), "token"), ShouldBeFalse)
		})

		Convey("An entry may pull and push at once", func() {
			combined := writePushConfig(t, `{
				"distSpecVersion": "1.1.1",
				"storage": {"rootDirectory": "/tmp/zot-push-config-test"},
				"http": {"address": "127.0.0.1", "port": "8080"},
				"extensions": {
					"sync": {
						"enable": true,
						"registries": [{
							"urls": ["https://dhi.io"],
							"onDemand": true,
							"pollInterval": "6h",
							"content": [{"prefix": "library/**"}],
							"push": {"enabled": true, "urls": ["https://zot.edge:5000"]}
						}]
					}
				}
			}`)

			conf := config.New()
			So(LoadConfiguration(conf, combined), ShouldBeNil)
			So(validateSync(conf, log.NewTestLogger()), ShouldBeNil)
		})
		Convey("A negative pollInterval is rejected", func() {
			negativePoll := writePushConfig(t, `{
				"distSpecVersion": "1.1.1",
				"storage": {"rootDirectory": "/tmp/zot-push-config-test"},
				"http": {"address": "127.0.0.1", "port": "8080"},
				"extensions": {
					"sync": {
						"enable": true,
						"registries": [{
							"pollInterval": "-1s",
							"content": [{"prefix": "library/**"}],
							"push": {"enabled": true, "urls": ["https://zot.edge:5000"]}
						}]
					}
				}
			}`)

			err := LoadConfiguration(config.New(), negativePoll)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "pollInterval")
		})

		Convey("push.platforms is validated", func() {
			invalidPlatform := writePushConfig(t, `{
				"distSpecVersion": "1.1.1",
				"storage": {"rootDirectory": "/tmp/zot-push-config-test"},
				"http": {"address": "127.0.0.1", "port": "8080"},
				"extensions": {
					"sync": {
						"enable": true,
						"registries": [{
							"pollInterval": "6h",
							"content": [{"prefix": "library/**"}],
							"push": {"enabled": true, "urls": ["https://zot.edge:5000"],
								"platforms": ["not a platform"]}
						}]
					}
				}
			}`)

			err := LoadConfiguration(config.New(), invalidPlatform)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "invalid push.platforms")

			validPlatform := writePushConfig(t, `{
				"distSpecVersion": "1.1.1",
				"storage": {"rootDirectory": "/tmp/zot-push-config-test"},
				"http": {"address": "127.0.0.1", "port": "8080"},
				"extensions": {
					"sync": {
						"enable": true,
						"registries": [{
							"pollInterval": "6h",
							"content": [{"prefix": "library/**"}],
							"push": {"enabled": true, "urls": ["https://zot.edge:5000"],
								"platforms": ["linux/amd64"]}
						}]
					}
				}
			}`)

			So(LoadConfiguration(config.New(), validPlatform), ShouldBeNil)
		})

		Convey("A rejected credential url is redacted in the log", func() {
			logPath := path.Join(t.TempDir(), "zot.log")
			logger := log.NewLogger("debug", logPath)

			enabled := true
			regCfg := syncconf.RegistryConfig{
				PollInterval: time.Hour,
				Content:      []syncconf.Content{{Prefix: "library/**"}},
				Push: &syncconf.PushConfig{
					Enabled: &enabled,
					URLs:    []string{"https://user:token@zot.edge:5000"},
				},
			}

			err := validateSyncPush(0, regCfg, logger)
			So(err, ShouldNotBeNil)
			So(strings.Contains(err.Error(), "token"), ShouldBeFalse)

			logged, readErr := os.ReadFile(logPath)
			So(readErr, ShouldBeNil)
			So(string(logged), ShouldContainSubstring, "xxxxx")
			So(strings.Contains(string(logged), "token"), ShouldBeFalse)
		})
	})
}
