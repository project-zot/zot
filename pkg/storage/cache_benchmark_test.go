package storage_test

import (
	"math/rand"
	"os/exec"
	"strings"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/cache"
)

const (
	region        string = "us-east-2"
	localEndpoint string = "http://localhost:4566"
	awsEndpoint   string = "https://dynamodb.us-east-2.amazonaws.com"
	datasetSize   int    = 5000
)

func generateRandomString() string {
	//nolint: gosec
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	charset := "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	randomBytes := make([]byte, 10)
	for i := range randomBytes {
		randomBytes[i] = charset[seededRand.Intn(len(charset))]
	}

	return string(randomBytes)
}

func generateData() map[godigest.Digest]string {
	dataMap := make(map[godigest.Digest]string, datasetSize)
	//nolint: gosec
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < datasetSize; i++ {
		randomString := generateRandomString()
		counter := 0

		for seededRand.Float32() < 0.5 && counter < 5 {
			counter++
			randomString += "/"
			randomString += generateRandomString()
		}
		digest := godigest.FromString(randomString)
		dataMap[digest] = randomString
	}

	return dataMap
}

func helperPutAll(cache cache.Cache, tableName string, testData map[godigest.Digest]string) {
	for digest, path := range testData {
		_ = cache.PutBlob(tableName, digest, path)
	}
}

func helperDeleteAll(cache cache.Cache, tableName string, testData map[godigest.Digest]string) {
	for digest, path := range testData {
		_ = cache.DeleteBlob(tableName, digest, path)
	}
}

func helperHasAll(cache cache.Cache, tableName string, testData map[godigest.Digest]string) {
	for digest, path := range testData {
		_ = cache.HasBlob(tableName, digest, path)
	}
}

func helperGetAll(cache cache.Cache, tableName string, testData map[godigest.Digest]string) {
	for digest := range testData {
		_, _ = cache.GetBlob(tableName, digest)
	}
}

func helperMix(cache cache.Cache, tableName string, testData map[godigest.Digest]string,
	digestSlice []godigest.Digest,
) {
	// The test data contains datasetSize entries by default, and each set of operations uses 5 entries
	for i := 0; i < 1000; i++ {
		_ = cache.PutBlob(tableName, digestSlice[i*5], testData[digestSlice[i*5]])
		_ = cache.PutBlob(tableName, digestSlice[i*5+1], testData[digestSlice[i*5+1]])
		_ = cache.PutBlob(tableName, digestSlice[i*5+2], testData[digestSlice[i*5+2]])
		_ = cache.PutBlob(tableName, digestSlice[i*5+2], testData[digestSlice[i*5+3]])
		_ = cache.DeleteBlob(tableName, digestSlice[i*5+1], testData[digestSlice[i*5+1]])
		_ = cache.DeleteBlob(tableName, digestSlice[i*5+2], testData[digestSlice[i*5+3]])
		_ = cache.DeleteBlob(tableName, digestSlice[i*5+2], testData[digestSlice[i*5+2]])
		_ = cache.HasBlob(tableName, digestSlice[i*5], testData[digestSlice[i*5]])
		_ = cache.HasBlob(tableName, digestSlice[i*5+1], testData[digestSlice[i*5+1]])
		_, _ = cache.GetBlob(tableName, digestSlice[i*5])
		_, _ = cache.GetBlob(tableName, digestSlice[i*5+1])
		_ = cache.PutBlob(tableName, digestSlice[i*5], testData[digestSlice[i*5+4]])
		_, _ = cache.GetBlob(tableName, digestSlice[i*5+4])
		_ = cache.DeleteBlob(tableName, digestSlice[i*5], testData[digestSlice[i*5+4]])
		_ = cache.DeleteBlob(tableName, digestSlice[i*5], testData[digestSlice[i*5]])
	}
}

func createCacheDriver(rootDir string) (cache.Cache, string) {
	log := log.NewLogger("error", "")

	cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir: rootDir,
		Name:    "cache_test",
	}, log)

	tableName := strings.ReplaceAll(rootDir, "/", "")

	err := cacheDriver.CreateBucket(tableName)
	if err != nil {
		panic(err)
	}

	return cacheDriver, tableName
}

// BoltDB tests

func BenchmarkPutLocal(b *testing.B) {
	dir := b.TempDir()
	cache, tableName := createCacheDriver(dir)
	testData := generateData()

	b.ResetTimer()

	helperPutAll(cache, tableName, testData)
}

func BenchmarkDeleteLocal(b *testing.B) {
	dir := b.TempDir()
	cache, tableName := createCacheDriver(dir)

	testData := generateData()

	for digest, path := range testData {
		_ = cache.PutBlob(tableName, digest, path)
	}

	b.ResetTimer()

	helperDeleteAll(cache, tableName, testData)
}

func BenchmarkHasLocal(b *testing.B) {
	dir := b.TempDir()
	cache, tableName := createCacheDriver(dir)

	testData := generateData()

	for digest, path := range testData {
		_ = cache.PutBlob(tableName, digest, path)
	}

	b.ResetTimer()

	helperHasAll(cache, tableName, testData)
}

func BenchmarkGetLocal(b *testing.B) {
	dir := b.TempDir()
	cache, tableName := createCacheDriver(dir)

	testData := generateData()
	counter := 1

	var previousDigest godigest.Digest

	for digest, path := range testData {
		if counter != 10 {
			_ = cache.PutBlob(tableName, digest, path)
			previousDigest = digest
			counter++
		} else {
			_ = cache.PutBlob(tableName, previousDigest, path)
			counter = 1
		}
	}

	b.ResetTimer()

	helperGetAll(cache, tableName, testData)
}

func BenchmarkMixLocal(b *testing.B) {
	dir := b.TempDir()
	cache, tableName := createCacheDriver(dir)

	testData := generateData()
	digestSlice := make([]godigest.Digest, datasetSize)
	counter := 0

	for key := range testData {
		digestSlice[counter] = key
		counter++
	}

	b.ResetTimer()

	helperMix(cache, tableName, testData, digestSlice)
}

// DynamoDB Local tests

func BenchmarkPutLocalstack(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", localEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint: localEndpoint,
		Region:   region,
	}, log)
	testData := generateData()

	b.ResetTimer()

	helperPutAll(cache, tableName, testData)
}

func BenchmarkDeleteLocalstack(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", localEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint: localEndpoint,
		Region:   region,
	}, log)
	testData := generateData()

	for digest, path := range testData {
		_ = cache.PutBlob(tableName, digest, path)
	}

	b.ResetTimer()

	helperDeleteAll(cache, tableName, testData)
}

func BenchmarkHasLocalstack(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", localEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint: localEndpoint,
		Region:   region,
	}, log)
	testData := generateData()

	for digest, path := range testData {
		_ = cache.PutBlob(tableName, digest, path)
	}

	b.ResetTimer()

	helperHasAll(cache, tableName, testData)
}

func BenchmarkGetLocalstack(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", localEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint: localEndpoint,
		Region:   region,
	}, log)
	testData := generateData()
	counter := 1

	var previousDigest godigest.Digest

	for digest, path := range testData {
		if counter != 10 {
			_ = cache.PutBlob(tableName, digest, path)
			previousDigest = digest
			counter++
		} else {
			_ = cache.PutBlob(tableName, previousDigest, path)
			counter = 1
		}
	}

	b.ResetTimer()

	helperGetAll(cache, tableName, testData)
}

func BenchmarkMixLocalstack(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", localEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint: localEndpoint,
		Region:   region,
	}, log)
	testData := generateData()
	digestSlice := make([]godigest.Digest, datasetSize)
	counter := 0

	for key := range testData {
		digestSlice[counter] = key
		counter++
	}

	b.ResetTimer()

	helperMix(cache, tableName, testData, digestSlice)
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
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint: awsEndpoint,
		Region:   region,
	}, log)
	testData := generateData()

	b.ResetTimer()

	helperPutAll(cache, tableName, testData)
}

func BenchmarkDeleteAWS(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", awsEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint: awsEndpoint,
		Region:   region,
	}, log)
	testData := generateData()

	for digest, path := range testData {
		_ = cache.PutBlob(tableName, digest, path)
	}

	b.ResetTimer()

	helperDeleteAll(cache, tableName, testData)
}

func BenchmarkHasAWS(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", awsEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint: awsEndpoint,
		Region:   region,
	}, log)
	testData := generateData()

	for digest, path := range testData {
		_ = cache.PutBlob(tableName, digest, path)
	}

	b.ResetTimer()

	helperHasAll(cache, tableName, testData)
}

func BenchmarkGetAWS(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", awsEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint: awsEndpoint,
		Region:   region,
	}, log)
	testData := generateData()
	counter := 1

	var previousDigest godigest.Digest

	for digest, path := range testData {
		if counter != 10 {
			_ = cache.PutBlob(tableName, digest, path)
			previousDigest = digest
			counter++
		} else {
			_ = cache.PutBlob(tableName, previousDigest, path)
			counter = 1
		}
	}

	b.ResetTimer()

	helperGetAll(cache, tableName, testData)
}

func BenchmarkMixAWS(b *testing.B) {
	log := log.NewLogger("error", "")
	tableName := generateRandomString()

	// Create Table
	_, err := exec.Command("aws", "dynamodb", "--region", region, "--endpoint-url", awsEndpoint, "create-table",
		"--table-name", tableName, "--attribute-definitions", "AttributeName=Digest,AttributeType=S",
		"--key-schema", "AttributeName=Digest,KeyType=HASH",
		"--billing-mode", "PAY_PER_REQUEST").Output()
	if err != nil {
		panic(err)
	}

	cache, _ := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint: awsEndpoint,
		Region:   region,
	}, log)
	testData := generateData()
	digestSlice := make([]godigest.Digest, datasetSize)
	counter := 0

	for key := range testData {
		digestSlice[counter] = key
		counter++
	}

	b.ResetTimer()

	helperMix(cache, tableName, testData, digestSlice)
}
