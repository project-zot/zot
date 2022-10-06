package constants

const (
	ArtifactSpecRoutePrefix      = "/oras/artifacts/v1"
	RoutePrefix                  = "/v2"
	Blobs                        = "blobs"
	Uploads                      = "uploads"
	DistAPIVersion               = "Docker-Distribution-API-Version"
	DistContentDigestKey         = "Docker-Content-Digest"
	BlobUploadUUID               = "Blob-Upload-UUID"
	DefaultMediaType             = "application/json"
	BinaryMediaType              = "application/octet-stream"
	DefaultMetricsExtensionRoute = "/metrics"
	// auth types.
	BearerAuth      = "Bearer"
	BasicAuth       = "Basic"
	CertificateAuth = "Certificate"
)
