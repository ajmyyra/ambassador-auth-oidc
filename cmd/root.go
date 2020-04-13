package cmd

import (
	"github.com/ajmyyra/ambassador-auth-oidc/pkg/authentication"
	"github.com/ajmyyra/ambassador-auth-oidc/pkg/authorization"
	"github.com/ajmyyra/ambassador-auth-oidc/pkg/daemon"
	"github.com/ajmyyra/ambassador-auth-oidc/pkg/util"
	"github.com/coreos/go-oidc"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
)

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

func Execute() {
	port, err := strconv.Atoi(getenvOrDefault("PORT", "8080"))
	if err != nil {
		log.Println("Parsing the port failed.")
		panic(err)
	}

	selfUrl := parseEnvURL("SELF_URL")
	clientID := parseEnvVar("CLIENT_ID")
	clientSecret := parseEnvVar("CLIENT_SECRET")
	oidcProvider := parseEnvURL("OIDC_PROVIDER")

	var oidcScopes []string
	// "openid" (oidc.ScopeOpenID) is a required scope for OpenID Connect flows.
	oidcScopes = append(oidcScopes, oidc.ScopeOpenID)
	for _, elem := range strings.Split(parseEnvVar("OIDC_SCOPES"), " ") {
		oidcScopes = append(oidcScopes, elem)
	}

	// 64 char(512 bit) key is needed for HS512
	hmacSecret := util.InitialiseHMACSecretFromEnv("JWT_HMAC_SECRET", 64)
	redisAddr := getenvOrDefault("REDIS_ADDRESS", "")
	redisPwd := getenvOrDefault("REDIS_PASSWORD", "")

	var whitelist []string
	tempWhitelist := strings.Split(getenvOrDefault("SKIP_AUTH_URI", ""), " ")
	if len(tempWhitelist[0]) > 0 {
		log.Println("Skipping authorization for URIs:", tempWhitelist)

		for _, item := range tempWhitelist {
			whitelist = append(whitelist, item)
		}
	} else {

	}

	logoutCookie := false
	if os.Getenv("LOGOUT_COOKIE") == "true" {
		logoutCookie = true
	}

	userInfo := true
	if os.Getenv("DISABLE_USERINFO") == "true" {
		userInfo = false
	}

	authZConfig := authorization.NewDefaultConfig(whitelist)

	authNConfig := authentication.AuthNConfig{
		SelfAddress:  *selfUrl,
		OIDCProvider: *oidcProvider,
		OIDCScopes:   oidcScopes,
		ClientId:     clientID,
		ClientSecret: clientSecret,
		JWTSecret:    hmacSecret,
		UserInfo:     userInfo,
		LogoutCookie: logoutCookie,
	}

	daemonConfig := daemon.NewDefaultConfig()
	daemonConfig.ListenPort = port

	redisConf := daemon.RedisConfig{
		Address:  redisAddr,
		Password: redisPwd,
	}

	daemon, err := daemon.New(daemonConfig, authNConfig, authZConfig, redisConf)
	if err != nil {
		log.Println("Daemon setup failed.")
		panic(err)
	}

	daemon.Initialize()
	daemon.Start()
}