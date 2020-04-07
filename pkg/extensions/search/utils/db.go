package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/boltdb/bolt"
)

/*Conn ... Create a database connection to */
func Conn(dbPath string) *bolt.DB {
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	return db
}

//CreateDB ...
func CreateDB(dbname string, db *bolt.DB) bool {
	uerr := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(dbname))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	})
	if uerr == nil {
		return true
	}
	return false
}

func updateNVD(schemas []Schema, mapList []map[string][]CVEId, db *bolt.DB) bool {
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("NvdJSON"))
		for _, schema := range schemas {
			encoded, err := json.Marshal(schema)
			err = b.Put([]byte(schema.CveID), encoded)
			if err != nil {
				return err
			}
		}
		return nil
	})
	uerr := updateNVDPkg("NvdPkgVendor", mapList[0], db)
	if uerr != nil {
		fmt.Println("Unable to Update Vendor Package Bucket")
		return false
	}
	uerr = updateNVDPkg("NvdPkgName", mapList[1], db)
	if uerr != nil {
		fmt.Println("Unable to Update Name Package Bucket")
		return false
	}
	//fmt.Println(mapList[2])
	uerr = updateNVDPkg("NvdPkgNameVer", mapList[2], db)
	if uerr != nil {
		fmt.Println("Unable to Update Name-Version Package Bucket")
		return false
	}
	if err != nil {
		return false
	}
	return true
}

/*UpdateNVD ... Updating the NVD database */
func updateNVDPkg(name string, pkgvendors map[string][]CVEId, db *bolt.DB) error {
	var dbcveidlist []CVEId
	//fmt.Println(db)
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(name))
		for pkgvendor, cveidlist := range pkgvendors {
			v := b.Get([]byte(pkgvendor))
			if v == nil {
				encode, _ := json.Marshal(cveidlist)
				b.Put([]byte(pkgvendor), encode)
			} else {
				err := json.Unmarshal(v, &dbcveidlist)
				if err != nil {
					fmt.Println("Unable to Unmarshal Data from PkgVendor Bucket")
					return err
				}
				cveidlist = append(cveidlist, dbcveidlist...)
				encode, _ := json.Marshal(cveidlist)
				b.Put([]byte(pkgvendor), encode)
			}
		}
		return nil
	})
	return err
}

/* Updating the NVD Meta Database */
func updateNVDMeta(filepath string, hashcode string, db *bolt.DB) bool {
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("NvdMeta"))
		err := b.Put([]byte(filepath), []byte(hashcode))
		if err != nil {
			return err
		}
		return nil
	})
	return true
}

// Method to check if file content is already present in DB
func isPresent(filename string, hashcode string, db *bolt.DB) bool {
	var v []byte
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("NvdMeta"))
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
	if res == 0 {
		return true
	}
	return false
}

/*IterateNvdData ... This function will iterate on full NVD Database and search the given package name, if found returns */
/*func IterateNvdData(db *bolt.DB, query string) []Schema {
	var schemas []Schema
	var schema Schema
	err := db.View(func(tx *bolt.Tx) error {
		// Assume bucket exists and has keys
		b := tx.Bucket([]byte("NvdJSON"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			// Unmarshalling the JSON
			err := json.Unmarshal(v, &schema)
			if err != nil {
				fmt.Println("Error Occured in Unmarshalling of JSON")
			}
			sc := Schema{}
			sc.CveID = schema.CveID
			sc.VulDesc = schema.VulDesc
			vuldetails := []VulDetail{}
			// Searching for package Name
			for _, desc := range schema.VulDetails {
				matched, _ := regexp.MatchString("^"+query, desc.PkgName)
				if matched {
					vuldetails = append(vuldetails, desc)
					continue
				}
				matched, _ = regexp.MatchString(query+"$", desc.PkgName)
				if matched {
					vuldetails = append(vuldetails, desc)
					continue
				}
				matched = strings.Contains(desc.PkgName, query)
				if matched {
					vuldetails = append(vuldetails, desc)
					continue
				}
			}
			if len(vuldetails) != 0 {
				sc.VulDetails = vuldetails
				schemas = append(schemas, sc)
			}

		}
		return nil
	})
	if err != nil {
		fmt.Println("Not able to search the database")
		fmt.Println(err)
	}
	return schemas
}*/

// SearchByCVEId ...
func SearchByCVEId(db *bolt.DB, key string) *Schema {
	var schema Schema
	db.View(func(tx *bolt.Tx) error {
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
	return &schema
}

// SearchByPkgType ...
func SearchByPkgType(name string, db *bolt.DB, key string) []CVEId {
	var cveidlist []CVEId
	db.View(func(tx *bolt.Tx) error {
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
	return cveidlist
}
