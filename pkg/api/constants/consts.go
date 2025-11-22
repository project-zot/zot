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
	// CreatePermission is an authz permission for create actions.
	CreatePermission = "create"
	// ReadPermission is an authz permission for read actions.
	ReadPermission = "read"
	// UpdatePermission is an authz permission for update actions.
	UpdatePermission = "update"
	// DeletePermission is an authz permission for delete actions.
	DeletePermission = "delete"
	// DetectManifestCollisionPermission is a behaviour action.
	DetectManifestCollisionPermission = "detectManifestCollision"
	// ScaleOutHopCountHeader is the zot scale-out hop count header.
	ScaleOutHopCountHeader = "X-Zot-Cluster-Hop-Count"
	// RepositoryLogKey is a log string key.
	// These can be used together with the logger to add context to a log message.
	RepositoryLogKey = "repository"
)
