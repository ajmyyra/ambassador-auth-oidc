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
	port = getenvOrDefault("PORT", "8080")
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

func getenvOrDefault(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		log.Println("No ", key, " specified, using '"+fallback+"' as default.")
		return fallback
	}
	return value
}

func scheduleBlacklistUpdater(seconds int) {
	for {
		time.Sleep(time.Duration(seconds) * time.Second)
		go updateBlacklist()
	}
}

func scheduleLoginSessionCleaner(seconds int) {
	for {
		time.Sleep(time.Duration(seconds) * time.Second)
		go removeOldLoginSessions()
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

	if redisdb != nil {
		updateBlacklist()
		go scheduleBlacklistUpdater(60)
	} else {
		go scheduleLoginSessionCleaner(300)
	}

	var listenPort = ":" + port
	log.Println("Starting web server at", listenPort)
	log.Fatal(http.ListenAndServe(listenPort, handlers.CORS()(router)))
}
