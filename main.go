package main

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

var port string

func init() {
	port := os.Getenv("PORT")
	if len(port) == 0 {
		log.Println("No port specified, using 8080 as default.")
		port = "8080" // default value if no PORT env variable is set
	}
}

func parseEnvURL(URLEnv string) *url.URL {
	envContent := os.Getenv(URLEnv)
	parsedURL, err := url.ParseRequestURI(envContent)
	if err != nil {
		log.Fatal("Not a valid URL for env variable ", URLEnv, ": ", envContent, "\n")
	}

	return parsedURL
}

func parseEnvVar(envVar string) string {
	envContent := os.Getenv(envVar)

	if len(envContent) == 0 {
		log.Fatal("Env variable ", envVar, " missing, exiting.")
	}

	return envContent
}

func scheduleBlacklistUpdater(seconds int) {
	for {
		time.Sleep(time.Duration(seconds) * time.Second)
		go updateBlacklist()
	}
}

// HealthHandler responds to /healthz endpoint for application monitoring
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	wh := newWildcardHandler()

	router := mux.NewRouter()
	router.HandleFunc("/healthz", HealthHandler).Methods(http.MethodGet)
	router.HandleFunc("/login/oidc", OIDCHandler).Methods(http.MethodGet)
	router.HandleFunc("/login", LoginHandler).Methods(http.MethodGet)
	router.HandleFunc("/logout", LogoutHandler).Methods(http.MethodGet)
	router.PathPrefix("/").Handler(wh)

	updateBlacklist()
	go scheduleBlacklistUpdater(60)

	log.Fatal(http.ListenAndServe(":8080", handlers.CORS()(router)))
}
