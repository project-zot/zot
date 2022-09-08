package meta

type MetadataStore interface {
	// datapath
	StorageMetadataStore // <- this is also an interface because backend driver can be boltdb or remote
	// user-data
	UserMetadataStore // <- same argument
	// add more later
}

// this is core functionality
// also, when graphQL is compiled in, it will call into here?
type StorageMetadataStore interface {
	// blobs
}

// this is an extension, so calls into this in "minimal" flavor return unsupported
type UserMetadataStore interface {
	// favorites. etc
}
