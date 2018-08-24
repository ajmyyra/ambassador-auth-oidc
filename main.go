package main

import (
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-redis/redis"
	"github.com/gorilla/mux"
)

var port string
var oidcScopes string
var clientID string
var clientSecret string

var redisdb *redis.Client
var redisAddr string
var redisPwd string

var authURL *url.URL
var selfURL *url.URL
var tokenURL *url.URL
var userinfoURL *url.URL

var nonceChars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func init() {
	rand.Seed(time.Now().UnixNano())

	authURL = parseEnvURL("AUTH_URL")
	selfURL = parseEnvURL("SELF_URL")
	tokenURL = parseEnvURL("TOKEN_URL")
	userinfoURL = parseEnvURL("USERINFO_URL")

	oidcScopes = parseEnvVar("OIDC_SCOPES")
	clientID = parseEnvVar("CLIENT_ID")
	clientSecret = parseEnvVar("CLIENT_SECRET")
	redisAddr = parseEnvVar("REDIS_ADDRESS")
	redisPwd = parseEnvVar("REDIS_PASSWORD")

	port := os.Getenv("PORT")
	if len(port) == 0 {
		log.Println("No port specified, using 8080 as default.")
		port = "8080" // default value if no PORT env variable is set
	}

	redisdb = redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPwd,
		DB:       0,
	})
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
