package version

import (
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"go.etcd.io/bbolt"
)

func GetBoltDBPatches() []func(DB *bbolt.DB) error {
	return []func(DB *bbolt.DB) error{}
}

func GetDynamoDBPatches() []func(client *dynamodb.Client, tableNames map[string]string) error {
	return []func(client *dynamodb.Client, tableNames map[string]string) error{}
}
