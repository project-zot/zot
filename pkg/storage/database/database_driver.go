package database

type Driver interface {
	// Returns the human-readable "name" of the driver.
	Name() string

	// Retrieves the blob matching provided digest.
	GetBlob(digest string) (string, error)

	// Uploads blob to database.
	PutBlob(digest, path string) error

	// Check if blob exists in database.
	HasBlob(digest, path string) bool

	// Delete a blob from the database.
	DeleteBlob(digest, path string) error
}

type Blob struct {
	Digest   string   `dynamodbav:"Digest,string"`
	BlobPath []string `dynamodbav:"BlobPath,stringset"`
}
