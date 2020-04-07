package api

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/anuvu/zot/pkg/extensions/search/utils"

	"github.com/boltdb/bolt"
	"github.com/gorilla/mux"
)

const dbPath = "../data/db/ZotSearch.db"

// DbContext ...
type DbContext struct {
	Db *bolt.DB
}

// RouteHandler ...
type RouteHandler struct {
	DbContext            DbContext
	ContextedHandlerFunc func(DbContext, http.ResponseWriter, *http.Request) (int, error)
}

func (handler RouteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	status, err := handler.ContextedHandlerFunc(handler.DbContext, w, r)
	if err != nil {
		log.Printf("HTTP %d: %q", status, err)
		switch status {
		// TODO you can handle any error that a router might return here.
		//
		}
	}
}

// Init ...
func Init() {
	dbcontext := DbContext{}
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		dbcontext.Db = utils.Conn(dbPath)
		nvdjsondb := utils.CreateDB("NvdJSON", dbcontext.Db)
		pkgvendordb := utils.CreateDB("NvdPkgVendor", dbcontext.Db)
		pkgnamedb := utils.CreateDB("NvdPkgName", dbcontext.Db)
		pkgnameverdb := utils.CreateDB("NvdPkgNameVer", dbcontext.Db)
		nvdmeatabd := utils.CreateDB("NvdMeta", dbcontext.Db)
		if !nvdjsondb || !nvdmeatabd || !pkgvendordb || !pkgnamedb || !pkgnameverdb {
			fmt.Println("Not able to Create Database")
		}
	} else {
		dbcontext.Db = utils.Conn(dbPath)
	}
	r := mux.NewRouter()
	defhandler := &RouteHandler{dbcontext, indexPage}
	r.Methods("GET").Path("/").Name("dhandler").Handler(defhandler)
	cvehandler := &RouteHandler{dbcontext, searchByCVEId}
	r.Methods("GET").Path("/cve/{CVEID}").Name("rhandler").Handler(cvehandler)
	pkgvendorhandler := &RouteHandler{dbcontext, searchByPkgVendor}
	r.Methods("GET").Path("/pkgvendor/{PKGVENDOR}").Name("pkgvendor").Handler(pkgvendorhandler)
	pkgnamehandler := &RouteHandler{dbcontext, searchByPkgName}
	r.Methods("GET").Path("/pkgname/{PKGNAME}").Name("pkgvendor").Handler(pkgnamehandler)
	pkgnamever := &RouteHandler{dbcontext, searchByPkgNameVer}
	r.Methods("GET").Path("/pkgnamever/{PKGVERSION}").Name("pkgversion").Handler(pkgnamever)
	updhandler := &RouteHandler{dbcontext, update}
	r.Methods("GET").Path("/update").Name("update").Handler(updhandler)
	http.ListenAndServe(":5000", r)

}
