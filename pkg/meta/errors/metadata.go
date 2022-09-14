package errors

import "errors"

var (
	ErrUnableToCreateUserBucket       = errors.New("unable to create a user bucket for user")
	ErrInvalidOldUserStarredRepos     = errors.New("invalid old entry for user starred repos")
	ErrUnmarshalledRepoListIsNil      = errors.New("list of repos is still nil")
	ErrCouldNotMarshalStarredRepos    = errors.New("could not repack entry for user starred repos")
	ErrCouldNotPersistData            = errors.New("could not persist to db")
	ErrInvalidOldUserBookmarkedRepos  = errors.New("invalid old entry for user bookmarked repos")
	ErrCouldNotMarshalBookmarkedRepos = errors.New("could not repack entry for user bookmarked repos")
	ErrInvalidUserBookmarkedRepos     = errors.New("invalid entry for user bookmarked repos")
)
