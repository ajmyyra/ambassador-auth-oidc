package main

import (
        "errors"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

var port string

func init() {
	port = os.Getenv("PORT")
	if len(port) == 0 {
		LogInfo("No port specified, using 8080 as default.")
		port = "8080"
	}
}

func parseEnvURL(URLEnv string) *url.URL {
	envContent := os.Getenv(URLEnv)
	parsedURL, err := url.ParseRequestURI(envContent)
	if err != nil {
		LogFatal(err, "Not a valid URL for env variable " + URLEnv + ": " + envContent)
	}

	return parsedURL
}

func parseEnvVar(envVar string) string {
	envContent := os.Getenv(envVar)

	if len(envContent) == 0 {
		LogFatal(errors.New("Env var missing."), "Env variable " + envVar + " missing, exiting.")
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

	var listenPort = ":" + port
	LogInfo("Starting web server at" + listenPort)
	LogFatal(http.ListenAndServe(listenPort, handlers.CORS()(router)), "http.ListenAndServe() failure.")
}
