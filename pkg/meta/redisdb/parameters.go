package redisdb

import (
	"github.com/redis/go-redis/v9"
)

type DBDriverParameters struct {
	URL       string
	KeyPrefix string
}

func GetRedisClient(params DBDriverParameters) (redis.UniversalClient, error) {
	// go-redis supports connecting via the redis uri specification (more convenient than parameter parsing)
	opts, err := redis.ParseURL(params.URL)
	if err != nil {
		return nil, err
	}

	return redis.NewClient(opts), nil
}
