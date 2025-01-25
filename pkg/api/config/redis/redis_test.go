package rediscfg_test

import (
	"os"
	"path"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/api/config"
	rediscfg "zotregistry.dev/zot/pkg/api/config/redis"
	"zotregistry.dev/zot/pkg/cli/server"
	"zotregistry.dev/zot/pkg/log"
)

func TestRedisOptions(t *testing.T) {
	Convey("Test redis initialization", t, func() {
		log := log.NewLogger("debug", "")
		So(log, ShouldNotBeNil)

		Convey("Test redis url parsing", func() {
			// Errors
			config := map[string]interface{}{"url": false}

			clientIntf, err := rediscfg.GetRedisClient(config, log)
			So(err, ShouldNotBeNil)
			So(clientIntf, ShouldBeNil)

			config = map[string]interface{}{"url": ""}

			clientIntf, err = rediscfg.GetRedisClient(config, log)
			So(err, ShouldNotBeNil)
			So(clientIntf, ShouldBeNil)

			config = map[string]interface{}{"url": "qwerty@localhost:6379/1?dial_timeout=5s"}

			clientIntf, err = rediscfg.GetRedisClient(config, log)
			So(err, ShouldNotBeNil)
			So(clientIntf, ShouldBeNil)

			config = map[string]interface{}{"url": "http://:qwerty@localhost:6379/1?dial_timeout=5s"}

			clientIntf, err = rediscfg.GetRedisClient(config, log)
			So(err, ShouldNotBeNil)
			So(clientIntf, ShouldBeNil)

			config = map[string]interface{}{"url": "http://localhost:6379/1?addr=host2:6379&addr=host1:6379"}

			clientIntf, err = rediscfg.GetRedisClient(config, log)
			So(err, ShouldNotBeNil)
			So(clientIntf, ShouldBeNil)

			// Success
			config = map[string]interface{}{"url": "redis://user:password@localhost:6379/1?dial_timeout=5s"}

			clientIntf, err = rediscfg.GetRedisClient(config, log)
			So(err, ShouldBeNil)
			So(clientIntf, ShouldNotBeNil)

			_, ok := clientIntf.(*redis.Client)
			So(ok, ShouldBeTrue)

			config = map[string]interface{}{"url": "redis://user:password@host1:6379?addr=host2:6379&addr=host1:6379"}

			clientIntf, err = rediscfg.GetRedisClient(config, log)
			So(err, ShouldBeNil)
			So(clientIntf, ShouldNotBeNil)

			_, ok = clientIntf.(*redis.ClusterClient)
			So(ok, ShouldBeTrue)
		})

		Convey("Test empty redis options from struct successfully", func() {
			config := map[string]interface{}{}

			// All attributes will have zero values
			options := rediscfg.ParseRedisUniversalOptions(config, log)
			So(options, ShouldNotBeNil)
			So(options.Addrs, ShouldEqual, []string(nil))
			So(options.DB, ShouldEqual, 0)
			So(options.MasterName, ShouldEqual, "")
			So(options.ClientName, ShouldEqual, "")
			So(options.Protocol, ShouldEqual, 0)
			So(options.Username, ShouldEqual, "")
			So(options.Password, ShouldEqual, "")
			So(options.SentinelUsername, ShouldEqual, "")
			So(options.SentinelPassword, ShouldEqual, "")
			So(options.DialTimeout, ShouldEqual, 0)
			So(options.MaxRetries, ShouldEqual, 0)
			So(options.MinRetryBackoff, ShouldEqual, 0)
			So(options.MaxRetryBackoff, ShouldEqual, 0)
			So(options.ReadTimeout, ShouldEqual, 0)
			So(options.WriteTimeout, ShouldEqual, 0)
			So(options.ContextTimeoutEnabled, ShouldEqual, false)
			So(options.PoolFIFO, ShouldEqual, false)
			So(options.PoolSize, ShouldEqual, 0)
			So(options.PoolTimeout, ShouldEqual, 0)
			So(options.MinIdleConns, ShouldEqual, 0)
			So(options.MaxIdleConns, ShouldEqual, 0)
			So(options.MaxActiveConns, ShouldEqual, 0)
			So(options.ConnMaxIdleTime, ShouldEqual, 0)
			So(options.ConnMaxLifetime, ShouldEqual, 0)
			So(options.MaxRedirects, ShouldEqual, 0)
			So(options.ReadOnly, ShouldEqual, false)
			So(options.RouteByLatency, ShouldEqual, false)
			So(options.RouteRandomly, ShouldEqual, false)
			So(options.DisableIndentity, ShouldEqual, false)
			So(options.IdentitySuffix, ShouldEqual, "")
			So(options.UnstableResp3, ShouldEqual, false)

			clientIntf, err := rediscfg.GetRedisClient(config, log)
			So(err, ShouldBeNil)
			So(clientIntf, ShouldNotBeNil)

			_, ok := clientIntf.(*redis.Client)
			So(ok, ShouldBeTrue)
		})

		Convey("Test redis options from struct successfully", func() {
			config := map[string]interface{}{
				"addr": []string{
					"a.repo:26379",
					"b.repo:26379",
					"c.repo:26379",
				},
				"db":                      1,
				"master_name":             "zotmeta",
				"client_name":             "client",
				"protocol":                3,
				"username":                "redis",
				"password":                "**secret**",
				"sentinel_username":       "sentinel",
				"sentinel_password":       "**secret**",
				"dial_timeout":            5 * time.Second,
				"max_retries":             5,
				"min_retry_backoff":       1 * time.Second,
				"max_retry_backoff":       3 * time.Second,
				"read_timeout":            1 * time.Second,
				"write_timeout":           1 * time.Second,
				"context_timeout_enabled": true,
				"pool_fifo":               false,
				"pool_size":               2,
				"pool_timeout":            10 * time.Second,
				"min_idle_conns":          1,
				"max_idle_conns":          2,
				"max_active_conns":        3,
				"conn_max_idle_time":      20 * time.Second,
				"conn_max_lifetime":       50 * time.Second,
				"max_redirects":           3,
				"read_only":               true,
				"route_by_latency":        false,
				"route_randomly":          true,
				"disable_identity":        false,
				"identity_suffix":         "test",
				"unstable_resp3":          true,
			}

			// All attribute values are taken from config
			options := rediscfg.ParseRedisUniversalOptions(config, log)
			So(options, ShouldNotBeNil)
			So(options.Addrs, ShouldEqual, []string{"a.repo:26379", "b.repo:26379", "c.repo:26379"})
			So(options.DB, ShouldEqual, 1)
			So(options.MasterName, ShouldEqual, "zotmeta")
			So(options.ClientName, ShouldEqual, "client")
			So(options.Protocol, ShouldEqual, 3)
			So(options.Username, ShouldEqual, "redis")
			So(options.Password, ShouldEqual, "**secret**")
			So(options.SentinelUsername, ShouldEqual, "sentinel")
			So(options.SentinelPassword, ShouldEqual, "**secret**")
			So(options.DialTimeout, ShouldEqual, 5*time.Second)
			So(options.MaxRetries, ShouldEqual, 5)
			So(options.MinRetryBackoff, ShouldEqual, 1*time.Second)
			So(options.MaxRetryBackoff, ShouldEqual, 3*time.Second)
			So(options.ReadTimeout, ShouldEqual, 1*time.Second)
			So(options.WriteTimeout, ShouldEqual, 1*time.Second)
			So(options.ContextTimeoutEnabled, ShouldEqual, true)
			So(options.PoolFIFO, ShouldEqual, false)
			So(options.PoolSize, ShouldEqual, 2)
			So(options.PoolTimeout, ShouldEqual, 10*time.Second)
			So(options.MinIdleConns, ShouldEqual, 1)
			So(options.MaxIdleConns, ShouldEqual, 2)
			So(options.MaxActiveConns, ShouldEqual, 3)
			So(options.ConnMaxIdleTime, ShouldEqual, 20*time.Second)
			So(options.ConnMaxLifetime, ShouldEqual, 50*time.Second)
			So(options.MaxRedirects, ShouldEqual, 3)
			So(options.ReadOnly, ShouldEqual, true)
			So(options.RouteByLatency, ShouldEqual, false)
			So(options.RouteRandomly, ShouldEqual, true)
			So(options.DisableIndentity, ShouldEqual, false)
			So(options.IdentitySuffix, ShouldEqual, "test")
			So(options.UnstableResp3, ShouldEqual, true)

			clientIntf, err := rediscfg.GetRedisClient(config, log)
			So(err, ShouldBeNil)
			So(clientIntf, ShouldNotBeNil)

			_, ok := clientIntf.(*redis.Client)
			So(ok, ShouldBeTrue)
		})

		Convey("Test redis options from struct with warnings", func() {
			config := map[string]interface{}{
				"addr":                    map[string]int{},
				"db":                      "somestring",
				"master_name":             map[string]int{},
				"client_name":             map[string]int{},
				"protocol":                "somestring",
				"username":                map[string]int{},
				"password":                map[string]int{},
				"sentinel_username":       map[string]int{},
				"sentinel_password":       map[string]int{},
				"dial_timeout":            "somestring",
				"max_retries":             "somestring",
				"min_retry_backoff":       "somestring",
				"max_retry_backoff":       "somestring",
				"read_timeout":            false,
				"write_timeout":           true,
				"context_timeout_enabled": "somestring",
				"pool_fifo":               "somestring",
				"pool_size":               "somestring",
				"pool_timeout":            "somestring",
				"min_idle_conns":          map[string]int{},
				"max_idle_conns":          map[string]int{},
				"max_active_conns":        "somestring",
				"conn_max_idle_time":      "somestring",
				"conn_max_lifetime":       "somestring",
				"max_redirects":           map[string]int{},
				"read_only":               map[string]int{},
				"route_by_latency":        "somestring",
				"route_randomly":          map[string]int{},
				"disable_identity":        "somestring",
				"identity_suffix":         map[string]int{},
				"unstable_resp3":          "somestring",
			}

			// All attributes remain with default values
			options := rediscfg.ParseRedisUniversalOptions(config, log)
			So(options, ShouldNotBeNil)
			So(options.Addrs, ShouldEqual, []string(nil))
			So(options.DB, ShouldEqual, 0)
			So(options.MasterName, ShouldEqual, "")
			So(options.ClientName, ShouldEqual, "")
			So(options.Protocol, ShouldEqual, 0)
			So(options.Username, ShouldEqual, "")
			So(options.Password, ShouldEqual, "")
			So(options.SentinelUsername, ShouldEqual, "")
			So(options.SentinelPassword, ShouldEqual, "")
			So(options.DialTimeout, ShouldEqual, 0)
			So(options.MaxRetries, ShouldEqual, 0)
			So(options.MinRetryBackoff, ShouldEqual, 0)
			So(options.MaxRetryBackoff, ShouldEqual, 0)
			So(options.ReadTimeout, ShouldEqual, 0)
			So(options.WriteTimeout, ShouldEqual, 0)
			So(options.ContextTimeoutEnabled, ShouldEqual, false)
			So(options.PoolFIFO, ShouldEqual, false)
			So(options.PoolSize, ShouldEqual, 0)
			So(options.PoolTimeout, ShouldEqual, 0)
			So(options.MinIdleConns, ShouldEqual, 0)
			So(options.MaxIdleConns, ShouldEqual, 0)
			So(options.MaxActiveConns, ShouldEqual, 0)
			So(options.ConnMaxIdleTime, ShouldEqual, 0)
			So(options.ConnMaxLifetime, ShouldEqual, 0)
			So(options.MaxRedirects, ShouldEqual, 0)
			So(options.ReadOnly, ShouldEqual, false)
			So(options.RouteByLatency, ShouldEqual, false)
			So(options.RouteRandomly, ShouldEqual, false)
			So(options.DisableIndentity, ShouldEqual, false)
			So(options.IdentitySuffix, ShouldEqual, "")
			So(options.UnstableResp3, ShouldEqual, false)

			clientIntf, err := rediscfg.GetRedisClient(config, log)
			So(err, ShouldBeNil)
			So(clientIntf, ShouldNotBeNil)

			_, ok := clientIntf.(*redis.Client)
			So(ok, ShouldBeTrue)
		})

		Convey("Test redis options from json", func(c C) {
			fileContent := []byte(`{
				"distSpecVersion": "1.1.0",
				"storage": {
					"remoteCache": true,
					"cacheDriver": {
						"name": "redis",
						"addr": [
							"a.repo:26379",
							"b.repo:26379",
							"c.repo:26379"
						],
						"db": 1,
						"master_name": "zotmeta",
						"username": "redis",
						"password": "**secret**",
						"dial_timeout": "5s"
					},
					"commit": false,
					"dedupe": false,
					"gc": true,
					"rootDirectory": "/data/zot-cache/dev"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080"
				},
				"log": {
					"level": "debug"
				}
			}`)

			dir := t.TempDir()
			configPath := path.Join(dir, "test-config.json")

			err := os.WriteFile(configPath, fileContent, 0o600)
			So(err, ShouldBeNil)

			conf := config.New()
			err = server.LoadConfiguration(conf, configPath)
			So(err, ShouldBeNil)

			options := rediscfg.ParseRedisUniversalOptions(conf.Storage.CacheDriver, log)
			So(options, ShouldNotBeNil)
			So(options.Addrs, ShouldEqual, []string{"a.repo:26379", "b.repo:26379", "c.repo:26379"})
			So(options.DB, ShouldEqual, 1)
			So(options.MasterName, ShouldEqual, "zotmeta")
			So(options.Username, ShouldEqual, "redis")
			So(options.Password, ShouldEqual, "**secret**")
			So(options.DialTimeout, ShouldEqual, 5*time.Second)

			clientIntf, err := rediscfg.GetRedisClient(conf.Storage.CacheDriver, log)
			So(err, ShouldBeNil)
			So(clientIntf, ShouldNotBeNil)

			_, ok := clientIntf.(*redis.Client)
			So(ok, ShouldBeTrue)
		})
	})
}
