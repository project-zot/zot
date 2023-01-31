package dynamo

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"

	"zotregistry.io/zot/pkg/meta/repodb/version"
	"zotregistry.io/zot/pkg/meta/userdb"
	dynamoParams "zotregistry.io/zot/pkg/meta/userdb/dynamodb-wrapper/params"
)

type DBWrapper struct {
	Client               *dynamodb.Client
	ApiKeyTablename      string
	UserProfileTablename string
	VersionTablename     string
	Patches              []func(client *dynamodb.Client, tableNames map[string]string) error
	Log                  log.Logger
}

func NewDynamoDBWrapper(params dynamoParams.DBDriverParameters) (*DBWrapper, error) {
	// custom endpoint resolver to point to localhost
	customResolver := aws.EndpointResolverWithOptionsFunc(
		func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				PartitionID:   "aws",
				URL:           params.Endpoint,
				SigningRegion: region,
			}, nil
		})

	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(params.Region),
		config.WithEndpointResolverWithOptions(customResolver))
	if err != nil {
		return nil, err
	}

	dynamoWrapper := DBWrapper{
		Client:               dynamodb.NewFromConfig(cfg),
		UserProfileTablename: params.UserProfileTablename,
		ApiKeyTablename:      params.ApiKeyTablename,
		VersionTablename:     params.VersionTablename,
		Patches:              version.GetDynamoDBPatches(),
		Log:                  log.Logger{Logger: zerolog.New(os.Stdout)},
	}

	err = dynamoWrapper.createVersionTable()
	if err != nil {
		return nil, err
	}

	err = dynamoWrapper.createApiKeyTable()
	if err != nil {
		return nil, err
	}

	err = dynamoWrapper.createUserProfileTable()
	if err != nil {
		return nil, err
	}

	// Using the Config value, create the DynamoDB client
	return &dynamoWrapper, nil
}

func (dwr *DBWrapper) PatchDB() error {
	DBVersion, err := dwr.getDBVersion()
	if err != nil {
		return errors.Wrapf(err, "patching dynamo failed, error retrieving database version")
	}

	if version.GetVersionIndex(DBVersion) == -1 {
		return errors.New("DB has broken format, no version found")
	}

	for patchIndex, patch := range dwr.Patches {
		if patchIndex < version.GetVersionIndex(DBVersion) {
			continue
		}

		tableNames := map[string]string{
			"ApiKeyTablename":      dwr.ApiKeyTablename,
			"UserProfileTablename": dwr.UserProfileTablename,
			"VersionTablename":     dwr.VersionTablename,
		}

		err := patch(dwr.Client, tableNames)
		if err != nil {
			return err
		}
	}

	return nil
}

func (dwr DBWrapper) createUserProfileTable() error {
	_, err := dwr.Client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String(dwr.UserProfileTablename),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("Email"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("Email"),
				KeyType:       types.KeyTypeHash,
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})

	if err != nil && !strings.Contains(err.Error(), "Table already exists") {
		return err
	}

	return dwr.waitTableToBeCreated(dwr.UserProfileTablename)
}

func (dwr DBWrapper) deleteUserProfileTable() error {
	_, err := dwr.Client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
		TableName: aws.String(dwr.UserProfileTablename),
	})

	if temp := new(types.ResourceNotFoundException); errors.As(err, &temp) {
		return nil
	}

	return dwr.waitTableToBeDeleted(dwr.UserProfileTablename)
}

func (dwr DBWrapper) ResetUserProfileTable() error {
	err := dwr.deleteUserProfileTable()
	if err != nil {
		return err
	}

	return dwr.createUserProfileTable()
}

func (dwr DBWrapper) waitTableToBeCreated(tableName string) error {
	const maxWaitTime = 20 * time.Second

	waiter := dynamodb.NewTableExistsWaiter(dwr.Client)

	return waiter.Wait(context.Background(), &dynamodb.DescribeTableInput{
		TableName: &tableName,
	}, maxWaitTime)
}

func (dwr DBWrapper) waitTableToBeDeleted(tableName string) error {
	const maxWaitTime = 20 * time.Second

	waiter := dynamodb.NewTableNotExistsWaiter(dwr.Client)

	return waiter.Wait(context.Background(), &dynamodb.DescribeTableInput{
		TableName: &tableName,
	}, maxWaitTime)
}

func (dwr DBWrapper) createApiKeyTable() error {
	_, err := dwr.Client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String(dwr.ApiKeyTablename),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("HashedKey"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("HashedKey"),
				KeyType:       types.KeyTypeHash,
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})

	if err != nil && !strings.Contains(err.Error(), "Table already exists") {
		return err
	}

	return dwr.waitTableToBeCreated(dwr.ApiKeyTablename)
}

func (dwr *DBWrapper) createVersionTable() error {
	_, err := dwr.Client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String(dwr.VersionTablename),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("VersionKey"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("VersionKey"),
				KeyType:       types.KeyTypeHash,
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})
	if err != nil {
		if strings.Contains(err.Error(), "Table already exists") {
			return nil
		}

		return err
	}

	err = dwr.waitTableToBeCreated(dwr.VersionTablename)
	if err != nil {
		return err
	}

	if err == nil {
		mdAttributeValue, err := attributevalue.Marshal(version.CurrentVersion)
		if err != nil {
			return err
		}

		_, err = dwr.Client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
			ExpressionAttributeNames: map[string]string{
				"#V": "Version",
			},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":Version": mdAttributeValue,
			},
			Key: map[string]types.AttributeValue{
				"VersionKey": &types.AttributeValueMemberS{
					Value: version.DBVersionKey,
				},
			},
			TableName:        aws.String(dwr.VersionTablename),
			UpdateExpression: aws.String("SET #V = :Version"),
		})

		if err != nil {
			return err
		}
	}

	return nil
}

func (dwr *DBWrapper) getDBVersion() (string, error) {
	resp, err := dwr.Client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.VersionTablename),
		Key: map[string]types.AttributeValue{
			"VersionKey": &types.AttributeValueMemberS{Value: version.DBVersionKey},
		},
	})
	if err != nil {
		return "", err
	}

	if resp.Item == nil {
		return "", nil
	}

	var version string

	err = attributevalue.Unmarshal(resp.Item["Version"], &version)
	if err != nil {
		return "", err
	}

	return version, nil
}

func (dwr DBWrapper) deleteApiKeyTable() error {
	_, err := dwr.Client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
		TableName: aws.String(dwr.ApiKeyTablename),
	})

	if temp := new(types.ResourceNotFoundException); errors.As(err, &temp) {
		return nil
	}

	return dwr.waitTableToBeDeleted(dwr.ApiKeyTablename)
}

func (dwr DBWrapper) ResetManifestDataTable() error {
	err := dwr.deleteApiKeyTable()
	if err != nil {
		return err
	}

	return dwr.createApiKeyTable()
}

func (dwr DBWrapper) AddUserAPIKey(hashedKey string, email string, apiKeyDetails *userdb.ApiKeyDetails) error {
	_, err := dwr.Client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#AK": "HashedKey",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":Email": &types.AttributeValueMemberS{Value: email},
		},
		Key: map[string]types.AttributeValue{
			"HashedKey": &types.AttributeValueMemberS{
				Value: hashedKey,
			},
		},
		TableName:        aws.String(dwr.UserProfileTablename),
		UpdateExpression: aws.String("SET #AK = :Email"),
	})
	if err != nil {
		return errors.Wrapf(err, "repodb: error while setting userProfile  for email %s", email)
	}

	userProfile, err := dwr.GetUserProfile(email)
	if err != nil {
		return errors.Wrapf(err, "repoDB: error while getting userProfile for email %s", email)
	}
	if userProfile.ApiKeys == nil {
		userProfile.ApiKeys = make(map[string]userdb.ApiKeyDetails)
	}

	userProfile.ApiKeys[hashedKey] = *apiKeyDetails

	err = dwr.SetUserProfile(email, userProfile)

	return err
}

func (dwr DBWrapper) DeleteUserAPIKey(id string, userEmail string) error {
	userProfile, err := dwr.GetUserProfile(userEmail)
	if err != nil {
		return errors.Wrapf(err, "repoDB: error while getting userProfile for email %s", userEmail)
	}

	for hash, apiKeyDetails := range userProfile.ApiKeys {
		if apiKeyDetails.UUID == id {
			delete(userProfile.ApiKeys, hash)

			_, err = dwr.Client.DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
				TableName: aws.String(dwr.ApiKeyTablename),
				Key: map[string]types.AttributeValue{
					"HashedKey": &types.AttributeValueMemberS{Value: hash},
				},
			})
			if err != nil {
				return errors.Wrapf(err, "repodb: error while deleting userAPIKey entry for hash %s", hash)
			}

			err := dwr.SetUserProfile(userEmail, userProfile)

			return err
		}
	}

	return nil
}

func (dwr DBWrapper) GetUserAPIKeyInfo(hashedKey string) (userdb.UserInfo, error) {
	var userInfo userdb.UserInfo
	resp, err := dwr.Client.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.ApiKeyTablename),
		Key: map[string]types.AttributeValue{
			"HashedKey": &types.AttributeValueMemberS{Value: hashedKey},
		},
	})
	if err != nil {
		return userdb.UserInfo{}, err
	}

	if resp.Item == nil {
		return userdb.UserInfo{}, zerr.ErrUserAPIKeyNotFound
	}

	err = attributevalue.Unmarshal(resp.Item["HashedKey"], &userInfo)
	if err != nil {
		return userdb.UserInfo{}, err
	}

	return userInfo, nil
}

func (dwr DBWrapper) GetUserProfile(email string) (userdb.UserProfile, error) {
	var userProfile userdb.UserProfile

	resp, err := dwr.Client.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(dwr.UserProfileTablename),
		Key: map[string]types.AttributeValue{
			"Email": &types.AttributeValueMemberS{Value: email},
		},
	})
	if err != nil {
		return userdb.UserProfile{}, err
	}

	if resp.Item == nil {
		return userdb.UserProfile{}, zerr.ErrUserAPIKeyNotFound
	}

	err = attributevalue.Unmarshal(resp.Item["UserProfile"], &userProfile)
	if err != nil {
		return userdb.UserProfile{}, err
	}

	return userProfile, nil
}

func (dwr DBWrapper) SetUserProfile(email string, userProfile userdb.UserProfile) error {
	upAttributeValue, err := attributevalue.Marshal(userProfile)
	if err != nil {
		return err
	}

	_, err = dwr.Client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#UP": "UserProfile",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":UserProfile": upAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"Email": &types.AttributeValueMemberS{
				Value: email,
			},
		},
		TableName:        aws.String(dwr.UserProfileTablename),
		UpdateExpression: aws.String("SET #UP = :UserProfile"),
	})

	return err
}

func (dwr DBWrapper) DeleteUserProfile(email string) error {
	_, err := dwr.Client.DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
		TableName: aws.String(dwr.UserProfileTablename),
		Key: map[string]types.AttributeValue{
			"Email": &types.AttributeValueMemberS{Value: email},
		},
	})

	return errors.Wrapf(err, "repodb: error while deleting userProfile  for email %s", email)
}
