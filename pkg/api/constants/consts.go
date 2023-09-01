package constants

import "time"

const (
	ArtifactSpecRoutePrefix      = "/oras/artifacts/v1"
	RoutePrefix                  = "/v2"
	Blobs                        = "blobs"
	Uploads                      = "uploads"
	DistAPIVersion               = "Docker-Distribution-API-Version"
	DistContentDigestKey         = "Docker-Content-Digest"
	SubjectDigestKey             = "OCI-Subject"
	BlobUploadUUID               = "Blob-Upload-UUID"
	DefaultMediaType             = "application/json"
	BinaryMediaType              = "application/octet-stream"
	DefaultMetricsExtensionRoute = "/metrics"
	CallbackBasePath             = "/auth/callback"
	LoginPath                    = "/auth/login"
	LogoutPath                   = "/auth/logout"
	APIKeyPath                   = "/auth/apikey" //nolint: gosec
	SessionClientHeaderName      = "X-ZOT-API-CLIENT"
	SessionClientHeaderValue     = "zot-ui"
	APIKeysPrefix                = "zak_"
	CallbackUIQueryParam         = "callback_ui"
	APIKeyTimeFormat             = time.RFC3339
	// authz permissions.
	// method actions.
	CreatePermission = "create"
	ReadPermission   = "read"
	UpdatePermission = "update"
	DeletePermission = "delete"
	// behaviour actions.
	DetectManifestCollisionPermission = "detectManifestCollision"
)
