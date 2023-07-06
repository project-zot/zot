package model

type SortCriteria string

type PageInput struct {
	Limit  int
	Offset int
	SortBy SortCriteria
}
