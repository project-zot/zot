package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/99designs/gqlgen/handler"
	"github.com/anuvu/zot/pkg/extensions/search"
	"github.com/anuvu/zot/pkg/extensions/search/utils"
	"github.com/boltdb/bolt"
)

const defaultPort = "8080"

const dbPath = "./data/db/ZotSearch.db"

func main() {
	var db *bolt.DB
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		db = utils.Conn(dbPath)
		nvdjsondb := utils.CreateDB("NvdJSON", db)
		pkgvendordb := utils.CreateDB("NvdPkgVendor", db)
		pkgnamedb := utils.CreateDB("NvdPkgName", db)
		pkgnameverdb := utils.CreateDB("NvdPkgNameVer", db)
		nvdmeatabd := utils.CreateDB("NvdMeta", db)
		if !nvdjsondb || !nvdmeatabd || !pkgvendordb || !pkgnamedb || !pkgnameverdb {
			fmt.Println("Not able to Create Database")
		}
	} else {
		db = utils.Conn(dbPath)
	}
	http.Handle("/", handler.Playground("GraphQL playground", "/query"))
	http.Handle("/query", handler.GraphQL(search.NewExecutableSchema(search.Config{Resolvers: &search.Resolver{Db: db}})))

	log.Printf("connect to http://localhost:%s/ for GraphQL playground", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
