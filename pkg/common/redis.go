package common

import (
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/cast"

	"zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/log"
)

func GetRedisClient(redisConfig map[string]interface{}, log log.Logger) (redis.UniversalClient, error) {
	// go-redis supports connecting via the redis uri specification (more convenient than parameter parsing)
	// Note failover/Sentinel cannot be configured via URL parsing at the moment
	if val, ok := redisConfig["url"]; ok {
		str, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("%w: cachedriver %s has invalid value for url", errors.ErrBadConfig, redisConfig)
		}

		// The cluster URL has additional addresses in query parameters
		if strings.Count(str, "addr") > 0 {
			opts, err := redis.ParseClusterURL(str)
			if err != nil {
				return nil, err
			}

			return redis.NewClusterClient(opts), nil
		}

		opts, err := redis.ParseURL(str)
		if err != nil {
			return nil, err
		}

		return redis.NewClient(opts), nil
	}

	// URL configuration not provided by the user, we need to initialize UniversalOptions based on the provided parameters
	opts := ParseRedisUniversalOptions(redisConfig, log)

	return redis.NewUniversalClient(opts), nil
}

func ParseRedisUniversalOptions(redisConfig map[string]interface{}, //nolint: gocyclo
	log log.Logger,
) *redis.UniversalOptions {
	opts := redis.UniversalOptions{}
	sanitizedConfig := map[string]interface{}{}

	for key, val := range redisConfig {
		if key == "password" || key == "sentinel_password" {
			sanitizedConfig[key] = "******"

			continue
		}

		sanitizedConfig[key] = val
	}

	log.Info().Interface("redisConfig", sanitizedConfig).Msg("parsing redis universal options")

	if val, ok := getStringSlice(redisConfig, "addr", log); ok {
		opts.Addrs = val
	}

	if val, ok := getString(redisConfig, "client_name", false, log); ok {
		opts.ClientName = val
	}

	if val, ok := getInt(redisConfig, "db", log); ok {
		opts.DB = val
	}

	if val, ok := getInt(redisConfig, "protocol", log); ok {
		opts.Protocol = val
	}

	if val, ok := getString(redisConfig, "username", false, log); ok {
		opts.Username = val
	}

	if val, ok := getString(redisConfig, "password", true, log); ok {
		opts.Password = val
	}

	if val, ok := getString(redisConfig, "sentinel_username", false, log); ok {
		opts.SentinelUsername = val
	}

	if val, ok := getString(redisConfig, "sentinel_password", true, log); ok {
		opts.SentinelPassword = val
	}

	if val, ok := getInt(redisConfig, "max_retries", log); ok {
		opts.MaxRetries = val
	}

	if val, ok := getDuration(redisConfig, "min_retry_backoff", log); ok {
		opts.MinRetryBackoff = val
	}

	if val, ok := getDuration(redisConfig, "max_retry_backoff", log); ok {
		opts.MaxRetryBackoff = val
	}

	if val, ok := getDuration(redisConfig, "dial_timeout", log); ok {
		opts.DialTimeout = val
	}

	if val, ok := getDuration(redisConfig, "read_timeout", log); ok {
		opts.ReadTimeout = val
	}

	if val, ok := getDuration(redisConfig, "write_timeout", log); ok {
		opts.WriteTimeout = val
	}

	if val, ok := getBool(redisConfig, "context_timeout_enabled", log); ok {
		opts.ContextTimeoutEnabled = val
	}

	if val, ok := getBool(redisConfig, "pool_fifo", log); ok {
		opts.PoolFIFO = val
	}

	if val, ok := getInt(redisConfig, "pool_size", log); ok {
		opts.PoolSize = val
	}

	if val, ok := getDuration(redisConfig, "pool_timeout", log); ok {
		opts.PoolTimeout = val
	}

	if val, ok := getInt(redisConfig, "min_idle_conns", log); ok {
		opts.MinIdleConns = val
	}

	if val, ok := getInt(redisConfig, "max_idle_conns", log); ok {
		opts.MaxIdleConns = val
	}

	if val, ok := getInt(redisConfig, "max_active_conns", log); ok {
		opts.MaxActiveConns = val
	}

	if val, ok := getDuration(redisConfig, "conn_max_idle_time", log); ok {
		opts.ConnMaxIdleTime = val
	}

	if val, ok := getDuration(redisConfig, "conn_max_lifetime", log); ok {
		opts.ConnMaxLifetime = val
	}

	if val, ok := getInt(redisConfig, "max_redirects", log); ok {
		opts.MaxRedirects = val
	}

	if val, ok := getBool(redisConfig, "read_only", log); ok {
		opts.ReadOnly = val
	}

	if val, ok := getBool(redisConfig, "route_by_latency", log); ok {
		opts.RouteByLatency = val
	}

	if val, ok := getBool(redisConfig, "route_randomly", log); ok {
		opts.RouteRandomly = val
	}

	if val, ok := getString(redisConfig, "master_name", false, log); ok {
		opts.MasterName = val
	}

	if val, ok := getBool(redisConfig, "disable_identity", log); ok {
		opts.DisableIndentity = val
	}

	if val, ok := getString(redisConfig, "identity_suffix", false, log); ok {
		opts.IdentitySuffix = val
	}

	if val, ok := getBool(redisConfig, "unstable_resp3", log); ok {
		opts.UnstableResp3 = val
	}

	log.Info().Msg("finished parsing redis universal options")

	return &opts
}

func logCastWarning(key string, value interface{}, hideValue bool, log log.Logger) {
	if hideValue {
		log.Warn().Str("key", key).Msg("failed to cast parameter to intended type")
	} else {
		log.Warn().Str("key", key).Interface("value", value).Msg("failed to cast parameter to intended type")
	}
}

func getBool(dict map[string]interface{}, key string, log log.Logger) (bool, bool) {
	value, ok := dict[key]
	if !ok {
		return false, false
	}

	ret, err := cast.ToBoolE(value)
	if err != nil {
		logCastWarning(key, value, false, log)

		return false, false
	}

	return ret, true
}

func getInt(dict map[string]interface{}, key string, log log.Logger) (int, bool) {
	value, ok := dict[key]
	if !ok {
		return 0, false
	}

	ret, err := cast.ToIntE(value)
	if err != nil {
		logCastWarning(key, value, false, log)

		return 0, false
	}

	return ret, true
}

func getString(dict map[string]interface{}, key string, hideValue bool, log log.Logger) (string, bool) {
	value, ok := dict[key]
	if !ok {
		return "", false
	}

	ret, err := cast.ToStringE(value)
	if err != nil {
		logCastWarning(key, value, hideValue, log)

		return "", false
	}

	return ret, true
}

func getStringSlice(dict map[string]interface{}, key string, log log.Logger) ([]string, bool) {
	value, ok := dict[key]
	if !ok {
		return []string{}, false
	}

	ret, err := cast.ToStringSliceE(value)
	if err != nil {
		logCastWarning(key, value, false, log)

		return []string{}, false
	}

	return ret, true
}

func getDuration(dict map[string]interface{}, key string, log log.Logger) (time.Duration, bool) {
	value, ok := dict[key]
	if !ok {
		return 0, false
	}

	ret, err := cast.ToDurationE(value)
	if err != nil {
		logCastWarning(key, value, false, log)

		return 0, false
	}

	return ret, true
}
