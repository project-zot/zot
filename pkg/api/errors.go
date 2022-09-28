package api

import (
	"zotregistry.io/zot/errors"
)

type Error struct {
	Code        string      `json:"code"`
	Message     string      `json:"message"`
	Description string      `json:"description"`
	Detail      interface{} `json:"detail,omitempty"`
}

type ErrorList struct {
	Errors []*Error `json:"errors"`
}

type ErrorCode int

//nolint:golint,stylecheck,revive
const (
	BLOB_UNKNOWN ErrorCode = iota
	BLOB_UPLOAD_INVALID
	BLOB_UPLOAD_UNKNOWN
	DIGEST_INVALID
	MANIFEST_BLOB_UNKNOWN
	MANIFEST_INVALID
	MANIFEST_UNKNOWN
	MANIFEST_UNVERIFIED
	NAME_INVALID
	NAME_UNKNOWN
	SIZE_INVALID
	TAG_INVALID
	UNAUTHORIZED
	DENIED
	UNSUPPORTED
	INVALID_INDEX
)

func (e ErrorCode) String() string {
	errMap := map[ErrorCode]string{
		BLOB_UNKNOWN:          "BLOB_UNKNOWN",
		BLOB_UPLOAD_INVALID:   "BLOB_UPLOAD_INVALID",
		BLOB_UPLOAD_UNKNOWN:   "BLOB_UPLOAD_UNKNOWN",
		DIGEST_INVALID:        "DIGEST_INVALID",
		MANIFEST_BLOB_UNKNOWN: "MANIFEST_BLOB_UNKNOWN",
		MANIFEST_INVALID:      "MANIFEST_INVALID",
		MANIFEST_UNKNOWN:      "MANIFEST_UNKNOWN",
		MANIFEST_UNVERIFIED:   "MANIFEST_UNVERIFIED",
		NAME_INVALID:          "NAME_INVALID",
		NAME_UNKNOWN:          "NAME_UNKNOWN",
		SIZE_INVALID:          "SIZE_INVALID",
		TAG_INVALID:           "TAG_INVALID",
		UNAUTHORIZED:          "UNAUTHORIZED",
		DENIED:                "DENIED",
		UNSUPPORTED:           "UNSUPPORTED",
		INVALID_INDEX:         "INVALID_INDEX",
	}

	return errMap[e]
}

func NewError(code ErrorCode, detail ...interface{}) Error {
	errMap := map[ErrorCode]Error{
		BLOB_UNKNOWN: {
			Message: "blob unknown to registry",
			Description: "blob unknown to registry 	This error MAY be returned when a blob is unknown " +
				" to the registry in a specified repository. This can be returned with a standard get or " +
				"if a manifest references an unknown layer during upload.",
		},

		BLOB_UPLOAD_INVALID: {
			Message:     "blob upload invalid",
			Description: `The blob upload encountered an error and can no longer proceed.`,
		},

		BLOB_UPLOAD_UNKNOWN: {
			Message:     "blob upload unknown to registry",
			Description: `If a blob upload has been cancelled or was never started, this error code MAY be returned.`,
		},

		DIGEST_INVALID: {
			Message: "provided digest did not match uploaded content",
			Description: "When a blob is uploaded, the registry will check that the content matches the " +
				"digest provided by the client. The error MAY include a detail structure with the key " +
				"\"digest\", including the invalid digest string. This error MAY also be returned when " +
				"a manifest includes an invalid layer digest.",
		},

		MANIFEST_BLOB_UNKNOWN: {
			Message: "blob unknown to registry",
			Description: `This error MAY be returned when a manifest blob is unknown
			to the registry.`,
		},

		MANIFEST_INVALID: {
			Message: "manifest invalid",
			Description: `During upload, manifests undergo several checks ensuring
			validity. If those checks fail, this error MAY be returned, unless a more
			specific error is included. The detail will contain information the failed
			validation.`,
		},

		MANIFEST_UNKNOWN: {
			Message: "manifest unknown",
			Description: `This error is returned when the manifest, identified by name
			and tag is unknown to the repository.`,
		},

		MANIFEST_UNVERIFIED: {
			Message: "manifest failed signature verification",
			Description: `During manifest upload, if the manifest fails signature
			verification, this error will be returned.`,
		},

		NAME_INVALID: {
			Message: "invalid repository name",
			Description: `Invalid repository name encountered either during manifest
			validation or any API operation.`,
		},

		NAME_UNKNOWN: {
			Message:     "repository name not known to registry",
			Description: `This is returned if the name used during an operation is unknown to the registry.`,
		},

		SIZE_INVALID: {
			Message: "provided length did not match content length",
			Description: "When a layer is uploaded, the provided size will be checked against the uploaded " +
				"content. If they do not match, this error will be returned.",
		},

		TAG_INVALID: {
			Message: "manifest tag did not match URI",
			Description: `During a manifest upload, if the tag in the manifest does
			not match the uri tag, this error will be returned.`,
		},

		UNAUTHORIZED: {
			Message: "authentication required",
			Description: `The access controller was unable to authenticate the client.
			Often this will be accompanied by a Www-Authenticate HTTP response header
			indicating how to authenticate.`,
		},

		DENIED: {
			Message: "requested access to the resource is denied",
			Description: `The access controller denied access for the operation on a
			resource.`,
		},

		UNSUPPORTED: {
			Message: "The operation is unsupported.",
			Description: `The operation was unsupported due to a missing
			implementation or invalid set of parameters.`,
		},

		INVALID_INDEX: {
			Message:     "Invalid format of index.json file of the repo",
			Description: "index.json file does not contain data in json format",
		},
	}

	err, ok := errMap[code]
	if !ok {
		panic(errors.ErrUnknownCode)
	}

	err.Code = code.String()
	err.Detail = detail

	return err
}

func NewErrorList(errors ...Error) ErrorList {
	errList := make([]*Error, 0)
	err := Error{}

	for _, e := range errors {
		err = e
		errList = append(errList, &err)
	}

	return ErrorList{errList}
}
