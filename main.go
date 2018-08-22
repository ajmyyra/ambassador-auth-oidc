package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

var port string

func init() {
	port := os.Getenv("PORT")
	if len(port) == 0 {
		log.Println("No port specified, using 8080 as default.")
		port = "8080" // default value if no port is set
	}

	if len(os.Getenv("CLIENT_ID")) == 0 {
		log.Fatal("No CLIENT_ID specified, exiting.")
	}
	if len(os.Getenv("CLIENT_SECRET")) == 0 {
		log.Fatal("No CLIENT_SECRET specified, exiting.")
	}
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/", AuthReqHandler)

	log.Fatal(http.ListenAndServe(":8080", router))
}
