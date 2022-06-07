package storage_test

import (
	"math/rand"
	"os/exec"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/database"
	"zotregistry.io/zot/pkg/storage/dynamodatabase"
)

const (
	region        string = "us-east-2"
	localEndpoint string = "http://localhost:4566"
	awsEndpoint   string = "https://dynamodb.us-east-2.amazonaws.com"
)

func generateRandomString() string {
	// nolint: gosec
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	charset := "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	randomBytes := make([]byte, 10)
	for i := range randomBytes {
		randomBytes[i] = charset[seededRand.Intn(len(charset))]
	}

	return string(randomBytes)
}

func generateData(sampleSize int) map[string]string {
	dataMap := make(map[string]string, sampleSize)
	// nolint: gosec
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < sampleSize; i++ {
		randomString := generateRandomString()
		counter := 0

		for seededRand.Float32() < 0.5 && counter < 5 {
			counter++
			randomString += "/"
			randomString += generateRandomString()
		}
		digest := godigest.FromString(randomString).String()
		dataMap[digest] = randomString
	}

	return dataMap
}

func helperPutAll(cache database.Driver, testData map[string]string) {
	for digest, path := range testData {
		_ = cache.PutBlob(digest, path)
	}
}

func helperDeleteAll(cache database.Driver, testData map[string]string) {
	for digest, path := range testData {
		_ = cache.DeleteBlob(digest, path)
	}
}

func helperHasAll(cache database.Driver, testData map[string]string) {
	for digest, path := range testData {
		_ = cache.HasBlob(digest, path)
	}
}

func helperGetAll(cache database.Driver, testData map[string]string) {
	for digest := range testData {
		_, _ = cache.GetBlob(digest)
	}
}

func helperMix(cache database.Driver, testData map[string]string, digestSlice []string) {
	// The test data contains 5000 entries by default, and each set of operations uses 5 entries
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
	cache, _ := database.Create("boltdb", storage.BoltDBDriverParameters{dir, "cache_test", false}, log)
	testData := generateData(5000)

	b.ResetTimer()

	helperPutAll(cache, testData)
}

func BenchmarkDeleteLocal(b *testing.B) {
	dir := b.TempDir()
	log := log.NewLogger("error", "")
	cache, _ := database.Create("boltdb", storage.BoltDBDriverParameters{dir, "cache_test", false}, log)
	testData := generateData(5000)

	for digest, path := range testData {
		_ = cache.PutBlob(digest, path)
	}

	b.ResetTimer()

	helperDeleteAll(cache, testData)
}

func BenchmarkHasLocal(b *testing.B) {
	dir := b.TempDir()
	log := log.NewLogger("error", "")
	cache, _ := database.Create("boltdb", storage.BoltDBDriverParameters{dir, "cache_test", false}, log)
	testData := generateData(5000)

	for digest, path := range testData {
		_ = cache.PutBlob(digest, path)
	}

	b.ResetTimer()

	helperHasAll(cache, testData)
}

func BenchmarkGetLocal(b *testing.B) {
	dir := b.TempDir()
	log := log.NewLogger("error", "")
	cache, _ := database.Create("boltdb", storage.BoltDBDriverParameters{dir, "cache_test", false}, log)
	testData := generateData(5000)
	previousDigest := ""
	counter := 1

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
	cache, _ := database.Create("boltdb", storage.BoltDBDriverParameters{dir, "cache_test", false}, log)
	testData := generateData(5000)
	digestSlice := make([]string, 5000)
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
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", localEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--provisioned-throughput", "ReadCapacityUnits=10,WriteCapacityUnits=5").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := database.Create("dynamodb", dynamodatabase.DynamoDBDriverParameters{
		Endpoint:  localEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData(5000)

	b.ResetTimer()

	helperPutAll(cache, testData)
}

func BenchmarkDeleteLocalstack(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", localEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--provisioned-throughput", "ReadCapacityUnits=10,WriteCapacityUnits=5").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := database.Create("dynamodb", dynamodatabase.DynamoDBDriverParameters{
		Endpoint:  localEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData(5000)

	for digest, path := range testData {
		_ = cache.PutBlob(digest, path)
	}

	b.ResetTimer()

	helperDeleteAll(cache, testData)
}

func BenchmarkHasLocalstack(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", localEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--provisioned-throughput", "ReadCapacityUnits=10,WriteCapacityUnits=5").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := database.Create("dynamodb", dynamodatabase.DynamoDBDriverParameters{
		Endpoint:  localEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData(5000)

	for digest, path := range testData {
		_ = cache.PutBlob(digest, path)
	}

	b.ResetTimer()

	helperHasAll(cache, testData)
}

func BenchmarkGetLocalstack(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", localEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--provisioned-throughput", "ReadCapacityUnits=10,WriteCapacityUnits=5").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := database.Create("dynamodb", dynamodatabase.DynamoDBDriverParameters{
		Endpoint:  localEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData(5000)
	previousDigest := ""
	counter := 1

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
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", localEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--provisioned-throughput", "ReadCapacityUnits=10,WriteCapacityUnits=5").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := database.Create("dynamodb", dynamodatabase.DynamoDBDriverParameters{
		Endpoint:  localEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData(5000)
	digestSlice := make([]string, 5000)
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
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", awsEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--provisioned-throughput", "ReadCapacityUnits=10,WriteCapacityUnits=5").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := database.Create("dynamodb", dynamodatabase.DynamoDBDriverParameters{
		Endpoint:  awsEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData(5000)

	b.ResetTimer()

	helperPutAll(cache, testData)
}

func BenchmarkDeleteAWS(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", awsEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--provisioned-throughput", "ReadCapacityUnits=10,WriteCapacityUnits=5").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := database.Create("dynamodb", dynamodatabase.DynamoDBDriverParameters{
		Endpoint:  awsEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData(5000)

	for digest, path := range testData {
		_ = cache.PutBlob(digest, path)
	}

	b.ResetTimer()

	helperDeleteAll(cache, testData)
}

func BenchmarkHasAWS(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", awsEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--provisioned-throughput", "ReadCapacityUnits=10,WriteCapacityUnits=5").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := database.Create("dynamodb", dynamodatabase.DynamoDBDriverParameters{
		Endpoint:  awsEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData(5000)

	for digest, path := range testData {
		_ = cache.PutBlob(digest, path)
	}

	b.ResetTimer()

	helperHasAll(cache, testData)
}

func BenchmarkGetAWS(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", awsEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--provisioned-throughput", "ReadCapacityUnits=10,WriteCapacityUnits=5").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := database.Create("dynamodb", dynamodatabase.DynamoDBDriverParameters{
		Endpoint:  awsEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData(5000)
	previousDigest := ""
	counter := 1

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
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", awsEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--provisioned-throughput", "ReadCapacityUnits=10,WriteCapacityUnits=5").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := database.Create("dynamodb", dynamodatabase.DynamoDBDriverParameters{
		Endpoint:  awsEndpoint,
		Region:    region,
		TableName: tableName,
	}, log)
	testData := generateData(5000)
	digestSlice := make([]string, 5000)
	counter := 0

	for key := range testData {
		digestSlice[counter] = key
		counter++
	}

	b.ResetTimer()

	helperMix(cache, testData, digestSlice)
}
