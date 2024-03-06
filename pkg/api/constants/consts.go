package constants

import "time"

const (
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
	AppNamespacePath             = "/zot"
	CallbackBasePath             = AppNamespacePath + "/auth/callback"
	LoginPath                    = AppNamespacePath + "/auth/login"
	LogoutPath                   = AppNamespacePath + "/auth/logout"
	APIKeyPath                   = AppNamespacePath + "/auth/apikey"
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
