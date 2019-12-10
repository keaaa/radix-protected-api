package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func homeLink(w http.ResponseWriter, r *http.Request) {
	log.Printf("Method %q, Request %q\n", r.Method, r.RequestURI)
	fmt.Fprintf(w, "Method %q, Request %q\n", r.Method, r.RequestURI)

	for k, v := range r.Header {
		fmt.Fprintf(w, "Header field %q, Value %q\n", k, v)
	}
}

func swagger(w http.ResponseWriter, r *http.Request) {
	dat, err := ioutil.ReadFile("/swagger/swagger.json")
	if err != nil {
		log.Printf("Failed to get swagger.json %v", err)
	}

	w.Header().Add("Content-Type", "application/json")
	fmt.Fprintf(w, "%s", string(dat))
}

func main() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/swagger.json", swagger)
	router.PathPrefix("/").HandlerFunc(homeLink)
	log.Fatal(http.ListenAndServe(":8080", router))
}
