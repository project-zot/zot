package iterator

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"zotregistry.io/zot/pkg/log"
)

type AttributesIterator interface {
	First(ctx context.Context) (types.AttributeValue, error)
	Next(ctx context.Context) (types.AttributeValue, error)
}

type BaseAttributesIterator struct {
	Client    *dynamodb.Client
	Table     string
	Attribute string

	itemBuffer       []map[string]types.AttributeValue
	currentItemIndex int
	lastEvaluatedKey map[string]types.AttributeValue
	readLimit        *int32

	log log.Logger
}

func NewBaseDynamoAttributesIterator(client *dynamodb.Client, table, attribute string, maxReadLimit int32,
	log log.Logger,
) *BaseAttributesIterator {
	var readLimit *int32

	if maxReadLimit > 0 {
		readLimit = &maxReadLimit
	}

	return &BaseAttributesIterator{
		Client:           client,
		Table:            table,
		Attribute:        attribute,
		itemBuffer:       []map[string]types.AttributeValue{},
		currentItemIndex: 0,
		readLimit:        readLimit,
		log:              log,
	}
}

func (dii *BaseAttributesIterator) First(ctx context.Context) (types.AttributeValue, error) {
	scanOutput, err := dii.Client.Scan(ctx, &dynamodb.ScanInput{
		TableName: aws.String(dii.Table),
		Limit:     dii.readLimit,
	})
	if err != nil {
		return nil, err
	}

	if len(scanOutput.Items) == 0 {
		return nil, nil
	}

	dii.itemBuffer = scanOutput.Items
	dii.lastEvaluatedKey = scanOutput.LastEvaluatedKey
	dii.currentItemIndex = 1

	return dii.itemBuffer[0][dii.Attribute], nil
}

func (dii *BaseAttributesIterator) Next(ctx context.Context) (types.AttributeValue, error) {
	if len(dii.itemBuffer) <= dii.currentItemIndex {
		if dii.lastEvaluatedKey == nil {
			return nil, nil
		}

		scanOutput, err := dii.Client.Scan(ctx, &dynamodb.ScanInput{
			TableName:         aws.String(dii.Table),
			ExclusiveStartKey: dii.lastEvaluatedKey,
		})
		if err != nil {
			return nil, err
		}

		// all items have been scanned
		if len(scanOutput.Items) == 0 {
			return nil, nil
		}

		dii.itemBuffer = scanOutput.Items
		dii.lastEvaluatedKey = scanOutput.LastEvaluatedKey
		dii.currentItemIndex = 0
	}

	nextItem := dii.itemBuffer[dii.currentItemIndex][dii.Attribute]
	dii.currentItemIndex++

	return nextItem, nil
}
