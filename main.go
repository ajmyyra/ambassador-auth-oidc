package main

import (
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/gorilla/mux"
)

var port string

func init() {

	checkEnvURL("AUTH_URL")
	checkEnvURL("SELF_URL")
	checkEnvURL("TOKEN_URL")
	checkEnvURL("USERINFO_URL")
	checkEnvVar("OIDC_SCOPES")
	checkEnvVar("CLIENT_ID")
	checkEnvVar("CLIENT_SECRET")

	port := os.Getenv("PORT")
	if len(port) == 0 {
		log.Println("No port specified, using 8080 as default.")
		port = "8080" // default value if no PORT env variable is set
	}
}

func checkEnvURL(URLEnv string) bool {
	envContent := os.Getenv(URLEnv)
	parsedURL, err := url.ParseRequestURI(envContent)
	if err != nil {
		log.Print("Not a valid URL for env variable ", URLEnv, ": ", envContent, "\n")
		panic(err)
	}
	log.Print("Setting from env var ", URLEnv, ": ", parsedURL, "\n")

	return true
}

func checkEnvVar(envVar string) {
	if len(os.Getenv(envVar)) == 0 {
		log.Fatal("Env variable ", envVar, " missing, exiting.")
	}
}

// HealthHandler responds to /healthz endpoint for application monitoring
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/healthz", HealthHandler)
	router.HandleFunc("/login/oidc", OIDCHandler)
	router.HandleFunc("/", AuthReqHandler)

	log.Fatal(http.ListenAndServe(":8080", router))
}
