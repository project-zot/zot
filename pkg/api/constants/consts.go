package constants

import "time"

const (
	RoutePrefix          = "/v2"
	Blobs                = "blobs"
	Uploads              = "uploads"
	DistAPIVersion       = "Docker-Distribution-API-Version"
	DistContentDigestKey = "Docker-Content-Digest"
	// OCITagResponseKey is returned on digest manifest pushes that include tag query
	// parameters (distribution-spec PR #600).
	OCITagResponseKey = "OCI-Tag"
	SubjectDigestKey  = "OCI-Subject"
	// MaxManifestDigestQueryTags is the maximum number of raw `tag=` query parameters accepted on
	// PUT .../manifests/<digest>?tag=... (draft OCI distribution-spec: registries MUST support at
	// least 10 and MAY respond with 414 beyond this limit). It uses the OCI tag max length (128;
	// must match pkg/regexp.TagMaxLen) and an ~8KiB request-target budget, reserving 2048 bytes
	// for path and digest:
	//
	//	(8192 - 2048) / (len("tag=") + 128 + 1) == 46
	MaxManifestDigestQueryTags = (8192 - 2048) / (len("tag=") + 128 + 1)
	// MaxManifestBodySize is the maximum number of bytes accepted for a manifest PUT request body.
	// OCI manifest JSON is always small metadata; 4 MiB is well above any realistic manifest.
	MaxManifestBodySize          = 4 * 1024 * 1024
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
	SchemeHTTP                   = "http"
	SchemeHTTPS                  = "https"
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
