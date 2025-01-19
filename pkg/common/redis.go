package common

import (
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/log"
)

func GetRedisClient(redisConfig map[string]interface{}, log log.Logger) (redis.UniversalClient, error) {
	// go-redis supports connecting via the redis uri specification (more convenient than parameter parsing)
	// Note failover/Sentinel cannot be configured via URL parsing at the moment
	if val, ok := redisConfig["url"]; ok {
		log.Info().Interface("redisConfig", redisConfig).Msg("parsing redis url")

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
	opts, err := ParseRedisUniversalOptions(redisConfig, log)
	if err != nil {
		return nil, err
	}

	return redis.NewUniversalClient(opts), nil
}

func ParseRedisUniversalOptions(redisConfig map[string]interface{}, //nolint: gocyclo
	log log.Logger,
) (*redis.UniversalOptions, error) {
	opts := redis.UniversalOptions{}

	log.Info().Interface("redisConfig", redisConfig).Msg("parsing redis universal options")

	if val, ok := getParamaterValue[[]string](redisConfig, "addr", log); ok {
		opts.Addrs = val
	}

	if val, ok := getParamaterValue[string](redisConfig, "client_name", log); ok {
		opts.ClientName = val
	}

	if val, ok := getParamaterValue[int](redisConfig, "db", log); ok {
		opts.DB = val
	}

	if val, ok := getParamaterValue[int](redisConfig, "protocol", log); ok {
		opts.Protocol = val
	}

	if val, ok := getParamaterValue[string](redisConfig, "username", log); ok {
		opts.Username = val
	}

	if val, ok := getParamaterValue[string](redisConfig, "password", log); ok {
		opts.Password = val
	}

	if val, ok := getParamaterValue[string](redisConfig, "sentinel_username", log); ok {
		opts.SentinelUsername = val
	}

	if val, ok := getParamaterValue[string](redisConfig, "sentinel_password", log); ok {
		opts.SentinelPassword = val
	}

	if val, ok := getParamaterValue[int](redisConfig, "max_retries", log); ok {
		opts.MaxRetries = val
	}

	if val, ok := getParamaterValue[time.Duration](redisConfig, "min_retry_backoff", log); ok {
		opts.MinRetryBackoff = val
	}

	if val, ok := getParamaterValue[time.Duration](redisConfig, "max_retry_backoff", log); ok {
		opts.MaxRetryBackoff = val
	}

	if val, ok := getParamaterValue[time.Duration](redisConfig, "dial_timeout", log); ok {
		opts.DialTimeout = val
	}

	if val, ok := getParamaterValue[time.Duration](redisConfig, "read_timeout", log); ok {
		opts.ReadTimeout = val
	}

	if val, ok := getParamaterValue[time.Duration](redisConfig, "write_timeout", log); ok {
		opts.WriteTimeout = val
	}

	if val, ok := getParamaterValue[bool](redisConfig, "context_timeout_enabled", log); ok {
		opts.ContextTimeoutEnabled = val
	}

	if val, ok := getParamaterValue[bool](redisConfig, "pool_fifo", log); ok {
		opts.PoolFIFO = val
	}

	if val, ok := getParamaterValue[int](redisConfig, "pool_size", log); ok {
		opts.PoolSize = val
	}

	if val, ok := getParamaterValue[time.Duration](redisConfig, "pool_timeout", log); ok {
		opts.PoolTimeout = val
	}

	if val, ok := getParamaterValue[int](redisConfig, "min_idle_conns", log); ok {
		opts.MinIdleConns = val
	}

	if val, ok := getParamaterValue[int](redisConfig, "max_idle_conns", log); ok {
		opts.MaxIdleConns = val
	}

	if val, ok := getParamaterValue[int](redisConfig, "max_active_conns", log); ok {
		opts.MaxActiveConns = val
	}

	if val, ok := getParamaterValue[time.Duration](redisConfig, "conn_max_idle_time", log); ok {
		opts.ConnMaxIdleTime = val
	}

	if val, ok := getParamaterValue[time.Duration](redisConfig, "conn_max_lifetime", log); ok {
		opts.ConnMaxLifetime = val
	}

	if val, ok := getParamaterValue[time.Duration](redisConfig, "connmaxlifetime", log); ok {
		opts.ConnMaxLifetime = val
	}

	if val, ok := getParamaterValue[int](redisConfig, "max_redirects", log); ok {
		opts.MaxRedirects = val
	}

	if val, ok := getParamaterValue[bool](redisConfig, "read_only", log); ok {
		opts.ReadOnly = val
	}

	if val, ok := getParamaterValue[bool](redisConfig, "route_by_latency", log); ok {
		opts.RouteByLatency = val
	}

	if val, ok := getParamaterValue[bool](redisConfig, "route_randomly", log); ok {
		opts.RouteRandomly = val
	}

	if val, ok := getParamaterValue[string](redisConfig, "master_name", log); ok {
		opts.MasterName = val
	}

	if val, ok := getParamaterValue[bool](redisConfig, "disable_identity", log); ok {
		opts.DisableIndentity = val
	}

	if val, ok := getParamaterValue[string](redisConfig, "identity_suffix", log); ok {
		opts.IdentitySuffix = val
	}

	if val, ok := getParamaterValue[bool](redisConfig, "unstable_resp3", log); ok {
		opts.UnstableResp3 = val
	}

	log.Info().Interface("RedisUniversalOptions", opts).Msg("finished parsing redis universal options")

	return &opts, nil
}

func getParamaterValue[T any](dict map[string]interface{}, key string, log log.Logger) (T, bool) {
	var ret T

	value, ok := dict[key]
	if !ok {
		return ret, false
	}

	ret, ok = value.(T)
	if !ok {
		log.Warn().Str("key", key).Interface("value", value).Msg("failed to cast parameter to intended type")

		return ret, false
	}

	return ret, true
}
