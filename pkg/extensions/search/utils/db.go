package utils

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/boltdb/bolt"
)

const (
	// NvdDB ...
	NvdDB = "NvdJSON"
	// VendorDB ...
	VendorDB = "NvdPkgVendor"
	// NameDB ...
	NameDB = "NvdPkgName"
	// NameverDB ...
	NameverDB = "NvdPkgNameVer"
	// NvdmetaDB ...
	NvdmetaDB = "NvdMeta"
)

/*Conn ... Create a database connection to */
func Conn(dbPath string) *bolt.DB {
	// Opening the connection on DB on given port
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return db
}

//CreateDB ...
func CreateDB(dbname string, db *bolt.DB) bool {
	// Creating the bucket on already open DB
	uerr := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(dbname))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	})

	return uerr == nil
}

func updateNVD(schemas []Schema, mapList []map[string][]CVEId, db *bolt.DB) bool {
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(NvdDB))

		for _, schema := range schemas {
			encoded, err := json.Marshal(schema)
			if err != nil {
				return err
			}

			err = b.Put([]byte(schema.CveID), encoded)
			if err != nil {
				return err
			}
		}
		return nil
	})

	uerr := updateNVDPkg(VendorDB, mapList[0], db)
	if uerr != nil {
		fmt.Println("Unable to Update Vendor Package Bucket")
		return false
	}

	uerr = updateNVDPkg(NameDB, mapList[1], db)
	if uerr != nil {
		fmt.Println("Unable to Update Name Package Bucket")

		return false
	}

	uerr = updateNVDPkg(NameverDB, mapList[2], db)
	if uerr != nil {
		fmt.Println("Unable to Update Name-Version Package Bucket")

		return false
	}

	return err == nil
}

/*UpdateNVD ... Updating the NVD database */
func updateNVDPkg(name string, pkgList map[string][]CVEId, db *bolt.DB) error {
	var dbcveidlist []CVEId

	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(name))
		for pkg, cveidlist := range pkgList {
			v := b.Get([]byte(pkg))
			if v == nil {
				encode, _ := json.Marshal(cveidlist)

				err := b.Put([]byte(pkg), encode)
				if err != nil {
					fmt.Println("Unable to Insert Data from PkgVendor Bucket")

					return err
				}
			} else {
				err := json.Unmarshal(v, &dbcveidlist)
				if err != nil {
					fmt.Println("Unable to Unmarshal Data from PkgVendor Bucket")

					return err
				}

				cveidlist = append(cveidlist, dbcveidlist...)

				encode, _ := json.Marshal(cveidlist)

				err = b.Put([]byte(pkg), encode)
				if err != nil {
					fmt.Println("Unable to Insert Data from PkgVendor Bucket")

					return err
				}
			}
		}

		return nil
	})

	return err
}

/* Updating the NVD Meta Database */
func updateNVDMeta(filepath string, hashcode string, db *bolt.DB) bool {
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("NvdMeta"))

		err := b.Put([]byte(filepath), []byte(hashcode))
		if err != nil {
			return err
		}

		return nil
	})

	return err == nil
}

// Method to check if file content is already present in DB
func isPresent(filename string, hashcode string, db *bolt.DB) bool {
	var v []byte

	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(NvdmetaDB))

		v = b.Get([]byte(filename))

		return nil
	})
	if err != nil {
		fmt.Println("Not able to search")
		fmt.Println(err)

		return false
	}

	if v == nil {
		return false
	}

	res := bytes.Compare(v, ([]byte)(hashcode))

	return res == 0
}

// SearchByCVEId ...
func SearchByCVEId(db *bolt.DB, key string) *Schema {
	var schema Schema

	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("NvdJSON"))

		v := b.Get([]byte(key))
		if v == nil {
			schema = Schema{}
		} else {
			err := json.Unmarshal(v, &schema)
			if err != nil {
				schema = Schema{}
			}
		}

		return nil
	})
	if err != nil {
		fmt.Println("Unable to search given CVEID")
	}

	return &schema
}

// SearchByPkgType ...
func SearchByPkgType(name string, db *bolt.DB, key string) []CVEId {
	var cveidlist []CVEId

	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(name))

		v := b.Get([]byte(key))
		if v == nil {
			cveidlist = []CVEId{}
		} else {
			err := json.Unmarshal(v, &cveidlist)
			if err != nil {
				fmt.Println(err)
				cveidlist = []CVEId{}
			}
		}

		return nil
	})
	if err != nil {
		fmt.Println("Unable to search given package")
	}

	return cveidlist
}
