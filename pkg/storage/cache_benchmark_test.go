package storage_test

import (
	"math/rand"
	"os/exec"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/cache"
	test "zotregistry.dev/zot/pkg/test/common"
)

const (
	region        string = "us-east-2"
	localEndpoint string = "http://localhost:4566"
	awsEndpoint   string = "https://dynamodb.us-east-2.amazonaws.com"
	datasetSize   int    = 5000
)

func generateData() map[godigest.Digest]string {
	dataMap := make(map[godigest.Digest]string, datasetSize)
	//nolint: gosec
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < datasetSize; i++ {
		randomString, _ := test.GenerateRandomString()
		counter := 0

		for seededRand.Float32() < 0.5 && counter < 5 {
			counter++
			randomString += "/"
			rs, _ := test.GenerateRandomString()
			randomString += rs
		}
		digest := godigest.FromString(randomString)
		dataMap[digest] = randomString
	}

	return dataMap
}

func helperPutAll(cache cache.Cache, testData map[godigest.Digest]string) {
	for digest, path := range testData {
		_ = cache.PutBlob(digest, path)
	}
}

func helperDeleteAll(cache cache.Cache, testData map[godigest.Digest]string) {
	for digest, path := range testData {
		_ = cache.DeleteBlob(digest, path)
	}
}

func helperHasAll(cache cache.Cache, testData map[godigest.Digest]string) {
	for digest, path := range testData {
		_ = cache.HasBlob(digest, path)
	}
}

func helperGetAll(cache cache.Cache, testData map[godigest.Digest]string) {
	for digest := range testData {
		_, _ = cache.GetBlob(digest)
	}
}

func helperMix(cache cache.Cache, testData map[godigest.Digest]string, digestSlice []godigest.Digest) {
	// The test data contains datasetSize entries by default, and each set of operations uses 5 entries
	for i := 0; i < 1000; i++ {
		_ = cache.PutBlob(digestSlice[i*5], testData[digestSlice[i*5]])
		_ = cache.PutBlob(digestSlice[i*5+1], testData[digestSlice[i*5+1]])
		_ = cache.PutBlob(digestSlice[i*5+2], testData[digestSlice[i*5+2]])
		_ = cache.PutBlob(digestSlice[i*5+2], testData[digestSlice[i*5+3]])
		_ = cache.DeleteBlob(digestSlice[i*5+1], testData[digestSlice[i*5+1]])
		_ = cache.DeleteBlob(digestSlice[i*5+2], testData[digestSlice[i*5+3]])
		_ = cache.DeleteBlob(digestSlice[i*5+2], testData[digestSlice[i*5+2]])
		_ = cache.HasBlob(digestSlice[i*5], testData[digestSlice[i*5]])
		_ = cache.HasBlob(digestSlice[i*5+1], testData[digestSlice[i*5+1]])
		_, _ = cache.GetBlob(digestSlice[i*5])
		_, _ = cache.GetBlob(digestSlice[i*5+1])
		_ = cache.PutBlob(digestSlice[i*5], testData[digestSlice[i*5+4]])
		_, _ = cache.GetBlob(digestSlice[i*5+4])
		_ = cache.DeleteBlob(digestSlice[i*5], testData[digestSlice[i*5+4]])
		_ = cache.DeleteBlob(digestSlice[i*5], testData[digestSlice[i*5]])
	}
}

// BoltDB tests

func BenchmarkPutLocal(b *testing.B) {
	dir := b.TempDir()
	log := log.NewLogger("error", "")
	cache, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     dir,
		Name:        "cache_test",
		UseRelPaths: false,
	}, log)
	testData := generateData()

	b.ResetTimer()

	helperPutAll(cache, testData)
}

func BenchmarkDeleteLocal(b *testing.B) {
	dir := b.TempDir()
	log := log.NewLogger("error", "")
	cache, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     dir,
		Name:        "cache_test",
		UseRelPaths: false,
	}, log)
	testData := generateData()

	for digest, path := range testData {
		_ = cache.PutBlob(digest, path)
	}

	b.ResetTimer()

	helperDeleteAll(cache, testData)
}

func BenchmarkHasLocal(b *testing.B) {
	dir := b.TempDir()
	log := log.NewLogger("error", "")
	cache, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     dir,
		Name:        "cache_test",
		UseRelPaths: false,
	}, log)
	testData := generateData()

	for digest, path := range testData {
		_ = cache.PutBlob(digest, path)
	}

	b.ResetTimer()

	helperHasAll(cache, testData)
}

func BenchmarkGetLocal(b *testing.B) {
	dir := b.TempDir()
	log := log.NewLogger("error", "")
	cache, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     dir,
		Name:        "cache_test",
		UseRelPaths: false,
	}, log)
	testData := generateData()
	counter := 1

	var previousDigest godigest.Digest

	for digest, path := range testData {
		if counter != 10 {
			_ = cache.PutBlob(digest, path)
			previousDigest = digest
			counter++
		} else {
			_ = cache.PutBlob(previousDigest, path)
			counter = 1
		}
	}

	b.ResetTimer()

	helperGetAll(cache, testData)
}

func BenchmarkMixLocal(b *testing.B) {
	dir := b.TempDir()
	log := log.NewLogger("error", "")
	cache, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     dir,
		Name:        "cache_test",
		UseRelPaths: false,
	}, log)
	testData := generateData()
	digestSlice := make([]godigest.Digest, datasetSize)
	counter := 0

	for key := range testData {
		digestSlice[counter] = key
		counter++
	}

	b.ResetTimer()

	helperMix(cache, testData, digestSlice)
}

// DynamoDB Local tests

func BenchmarkPutLocalstack(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName, seed := test.GenerateRandomString()
	log.Info().Int64("seed", seed).Msg("random seed for tableName")

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", localEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint:  localEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData()

	b.ResetTimer()

	helperPutAll(cache, testData)
}

func BenchmarkDeleteLocalstack(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName, seed := test.GenerateRandomString()
	log.Info().Int64("seed", seed).Msg("random seed for tableName")

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", localEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint:  localEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData()

	for digest, path := range testData {
		_ = cache.PutBlob(digest, path)
	}

	b.ResetTimer()

	helperDeleteAll(cache, testData)
}

func BenchmarkHasLocalstack(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName, seed := test.GenerateRandomString()
	log.Info().Int64("seed", seed).Msg("random seed for tableName")

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", localEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint:  localEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData()

	for digest, path := range testData {
		_ = cache.PutBlob(digest, path)
	}

	b.ResetTimer()

	helperHasAll(cache, testData)
}

func BenchmarkGetLocalstack(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName, seed := test.GenerateRandomString()
	log.Info().Int64("seed", seed).Msg("random seed for tableName")

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", localEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint:  localEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData()
	counter := 1

	var previousDigest godigest.Digest

	for digest, path := range testData {
		if counter != 10 {
			_ = cache.PutBlob(digest, path)
			previousDigest = digest
			counter++
		} else {
			_ = cache.PutBlob(previousDigest, path)
			counter = 1
		}
	}

	b.ResetTimer()

	helperGetAll(cache, testData)
}

func BenchmarkMixLocalstack(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName, seed := test.GenerateRandomString()
	log.Info().Int64("seed", seed).Msg("random seed for tableName")

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", localEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint:  localEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData()
	digestSlice := make([]godigest.Digest, datasetSize)
	counter := 0

	for key := range testData {
		digestSlice[counter] = key
		counter++
	}

	b.ResetTimer()

	helperMix(cache, testData, digestSlice)
}

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// DANGER ZONE: tests with true AWS endpoint
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

func BenchmarkPutAWS(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName, seed := test.GenerateRandomString()
	log.Info().Int64("seed", seed).Msg("random seed for tableName")

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", awsEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint:  awsEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData()

	b.ResetTimer()

	helperPutAll(cache, testData)
}

func BenchmarkDeleteAWS(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName, seed := test.GenerateRandomString()
	log.Info().Int64("seed", seed).Msg("random seed for tableName")

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", awsEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint:  awsEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData()

	for digest, path := range testData {
		_ = cache.PutBlob(digest, path)
	}

	b.ResetTimer()

	helperDeleteAll(cache, testData)
}

func BenchmarkHasAWS(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName, seed := test.GenerateRandomString()
	log.Info().Int64("seed", seed).Msg("random seed for tableName")

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", awsEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint:  awsEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData()

	for digest, path := range testData {
		_ = cache.PutBlob(digest, path)
	}

	b.ResetTimer()

	helperHasAll(cache, testData)
}

func BenchmarkGetAWS(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName, seed := test.GenerateRandomString()
	log.Info().Int64("seed", seed).Msg("random seed for tableName")

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", awsEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint:  awsEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData()
	counter := 1

	var previousDigest godigest.Digest

	for digest, path := range testData {
		if counter != 10 {
			_ = cache.PutBlob(digest, path)
			previousDigest = digest
			counter++
		} else {
			_ = cache.PutBlob(previousDigest, path)
			counter = 1
		}
	}

	b.ResetTimer()

	helperGetAll(cache, testData)
}

func BenchmarkMixAWS(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName, seed := test.GenerateRandomString()
	log.Info().Int64("seed", seed).Msg("random seed for tableName")

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", awsEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint:  awsEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData()
	digestSlice := make([]godigest.Digest, datasetSize)
	counter := 0

	for key := range testData {
		digestSlice[counter] = key
		counter++
	}

	b.ResetTimer()

	helperMix(cache, testData, digestSlice)
}
