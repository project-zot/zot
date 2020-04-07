package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/anuvu/zot/pkg/extensions/search/utils"

	"github.com/gorilla/mux"
)

func indexPage(d DbContext, w http.ResponseWriter, r *http.Request) (int, error) {
	fmt.Fprintln(w, "Welcome to Zot Search API ")
	return http.StatusOK, nil
}
func searchByCVEId(d DbContext, w http.ResponseWriter, r *http.Request) (int, error) {
	vars := mux.Vars(r)
	name, _ := vars["CVEID"]
	ans := utils.SearchByCVEId(d.Db, name)
	jsonAnd, _ := json.Marshal(ans)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonAnd)
	return http.StatusOK, nil
}
func searchByPkgName(d DbContext, w http.ResponseWriter, r *http.Request) (int, error) {
	vars := mux.Vars(r)
	name, _ := vars["PKGNAME"]
	ans := utils.SearchByPkgType("NvdPkgName", d.Db, name)
	jsonAnd, _ := json.Marshal(ans)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonAnd)
	return http.StatusOK, nil
}

func searchByPkgVendor(d DbContext, w http.ResponseWriter, r *http.Request) (int, error) {
	vars := mux.Vars(r)
	name, _ := vars["PKGVENDOR"]
	ans := utils.SearchByPkgType("NvdPkgVendor", d.Db, name)
	jsonAnd, _ := json.Marshal(ans)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonAnd)
	return http.StatusOK, nil
}

func searchByPkgNameVer(d DbContext, w http.ResponseWriter, r *http.Request) (int, error) {
	vars := mux.Vars(r)
	name, _ := vars["PKGVERSION"]
	ans := utils.SearchByPkgType("NvdPkgNameVer", d.Db, name)
	jsonAnd, _ := json.Marshal(ans)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonAnd)
	return http.StatusOK, nil
}
func update(d DbContext, w http.ResponseWriter, r *http.Request) (int, error) {
	fmt.Println("Started Update")
	err := utils.GetNvdData("../data", 2002, 2003, d.Db)
	if err != nil {
		fmt.Fprintln(w, "Error Updating the database")
	}
	fmt.Fprintln(w, "Database Updated")
	return http.StatusOK, nil
}
