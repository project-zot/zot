package utils

import (
	"testing"
)

func TestUtil(t *testing.T) {
	db := Conn("./testdata/db/Test.db")
	if db == nil {
		t.Fatal("Unable to open db")
	}
	err := GetNvdData("./testdata/", 2002, 2003, db)
	if err != nil {
		t.Fatal("Unable to Get the Data")
	}
}
