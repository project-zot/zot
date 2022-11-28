package dynamo_test

import (
	"context"
	"os"
	"testing"

	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/log"
	dynamo "zotregistry.io/zot/pkg/meta/repodb/dynamodb-wrapper"
)

func TestIterator(t *testing.T) {
	const (
		endpoint = "http://localhost:4566"
		region   = "us-east-2"
	)

	Convey("TestIterator", t, func() {
		dynamoWrapper, err := dynamo.NewDynamoDBWrapper(dynamo.DBDriverParameters{
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     "RepoMetadataTable",
			ManifestMetaTablename: "ManifestMetadataTable",
		})
		So(err, ShouldBeNil)

		So(dynamoWrapper.ResetManifestMetaTable(), ShouldBeNil)
		So(dynamoWrapper.ResetRepoMetaTable(), ShouldBeNil)

		err = dynamoWrapper.SetRepoTag("repo1", "tag1", "manifestDigest1")
		So(err, ShouldBeNil)

		err = dynamoWrapper.SetRepoTag("repo2", "tag2", "manifestDigest2")
		So(err, ShouldBeNil)

		err = dynamoWrapper.SetRepoTag("repo3", "tag3", "manifestDigest3")
		So(err, ShouldBeNil)

		repoMetaAttributeIterator := dynamo.NewBaseDynamoAttributesIterator(
			dynamoWrapper.Client,
			"RepoMetadataTable",
			"RepoMetadata",
			1,
			log.Logger{Logger: zerolog.New(os.Stdout)},
		)

		attribute, err := repoMetaAttributeIterator.First(context.Background())
		So(err, ShouldBeNil)
		So(attribute, ShouldNotBeNil)

		attribute, err = repoMetaAttributeIterator.Next(context.Background())
		So(err, ShouldBeNil)
		So(attribute, ShouldNotBeNil)

		attribute, err = repoMetaAttributeIterator.Next(context.Background())
		So(err, ShouldBeNil)
		So(attribute, ShouldNotBeNil)

		attribute, err = repoMetaAttributeIterator.Next(context.Background())
		So(err, ShouldBeNil)
		So(attribute, ShouldBeNil)
	})
}
