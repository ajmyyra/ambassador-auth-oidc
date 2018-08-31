package main

import (
	"context"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	oidc "github.com/ajmyyra/go-oidc"
	"github.com/go-redis/redis"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
)

var port string
var hostname string

var redisdb *redis.Client

var ctx context.Context
var oauth2Config oauth2.Config
var oidcProvider *oidc.Provider
var oidcConfig *oidc.Config

func init() {
	rand.Seed(time.Now().UnixNano())

	clientID := parseEnvVar("CLIENT_ID")
	clientSecret := parseEnvVar("CLIENT_SECRET")
	redisAddr := parseEnvVar("REDIS_ADDRESS")
	redisPwd := parseEnvVar("REDIS_PASSWORD")
	hostname = strings.Split(parseEnvURL("SELF_URL").Host, ":")[0] // Because Host still has port if it was in URL

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

	ctx = context.Background()

	provider, err := oidc.NewProvider(ctx, parseEnvURL("OIDC_PROVIDER").String())
	if err != nil {
		log.Fatal("OIDC provider setup failed: ", err)
	}

	oidcConfig = &oidc.Config{
		ClientID: clientID,
	}

	var oidcScopes []string

	// "openid" (oidc.ScopeOpenID) is a required scope for OpenID Connect flows.
	oidcScopes = append(oidcScopes, oidc.ScopeOpenID)
	for _, elem := range strings.Split(parseEnvVar("OIDC_SCOPES"), " ") {
		oidcScopes = append(oidcScopes, elem)
	}

	oauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  parseEnvURL("SELF_URL").String() + "/login/oidc",

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		Scopes: oidcScopes,
	}

	oidcProvider = provider
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
	router.HandleFunc("/login", LoginHandler)
	// router.HandleFunc("/logout", LogoutHandler) // TODO
	router.HandleFunc("/", AuthReqHandler) // TODO convert to wildcard

	log.Fatal(http.ListenAndServe(":8080", router))
}
