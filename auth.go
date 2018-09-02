package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/go-redis/redis"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

var hostname string
var redisdb *redis.Client
var ctx context.Context
var oauth2Config oauth2.Config
var oidcProvider *oidc.Provider
var oidcConfig *oidc.Config

var nonceChars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
var secCookie *securecookie.SecureCookie

func init() {
	hostname = strings.Split(parseEnvURL("SELF_URL").Host, ":")[0] // Because Host still has port if it was in URL

	redisAddr := parseEnvVar("REDIS_ADDRESS")
	redisPwd := parseEnvVar("REDIS_PASSWORD")
	redisdb = redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPwd,
		DB:       0,
	})

	rand.Seed(time.Now().UnixNano())

	clientID := parseEnvVar("CLIENT_ID")
	clientSecret := parseEnvVar("CLIENT_SECRET")

	var hashKey = getSecureValue("SEC_HASHKEY", 64)
	var blockKey = getSecureValue("SEC_BLOCKKEY", 32)
	secCookie = securecookie.New(hashKey, blockKey)

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

// LoginHandler processes login requests
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	beginOIDCLogin(w, r, "/")
}

// AuthReqHandler processes all incoming requests by default, unless specific endpoint is mentioned
func AuthReqHandler(w http.ResponseWriter, r *http.Request) {
	// TODO CORS check, others?
	// TODO add user from userinfo to logs

	cookie, err := r.Cookie("auth")
	if err != nil {
		log.Println("Cookie not set, redirecting to login.")
		beginOIDCLogin(w, r, r.URL.Path)
		return
	}

	if len(cookie.Value) == 0 { // No auth header set
		log.Println("Empty authorization header.")
		returnStatus(w, http.StatusBadRequest, "Cookie empty or malformed.")
	} else {

		var cookieContent []byte
		secCookie.Decode("userinfo", cookie.Value, &cookieContent)

		cookieHash := hashString(cookie.Value)

		userInfoClaims, err := redisdb.Get(cookieHash).Result()
		if err != nil {
			log.Println("Session not found for", cookieHash)
			returnStatus(w, http.StatusForbidden, "Session not found.")
			return
		}

		if strings.Compare(string(cookieContent[:]), userInfoClaims) == 0 {
			log.Println("Validated and accepted a request to", r.URL.String())
			w.Header().Set("X-Auth-Userinfo", userInfoClaims)
			returnStatus(w, http.StatusOK, "OK")
		} else {
			log.Println("Cookie validation failed, cookie and DB differ.")
			returnStatus(w, http.StatusForbidden, "Incorrect cookie.")
		}
	}
}

// OIDCHandler processes AuthN responses from OpenID Provider, exchanges token to userinfo and establishes user session
func OIDCHandler(w http.ResponseWriter, r *http.Request) {
	var authCode = r.FormValue("code")
	if len(authCode) == 0 {
		log.Println("Missing url parameter: code")
		returnStatus(w, http.StatusBadRequest, "Missing url parameter: code")
		return
	}

	var state = r.FormValue("state")
	if len(state) == 0 {
		log.Println("Missing url parameter: state")
		returnStatus(w, http.StatusBadRequest, "Missing url parameter: state")
		return
	}

	// Getting original destination from DB with state
	destination, err := redisdb.Get(state).Result()
	if err != nil {
		if err.Error() == "redis: nil" { // State didn't exist, redirecting to new login
			log.Print("No state found with ", state, ", starting new auth session.\n")
			beginOIDCLogin(w, r, "/")
			return
		}

		returnStatus(w, http.StatusInternalServerError, "Error fetching state from DB.")
		panic(err)
	}

	oauth2Token, err := oauth2Config.Exchange(ctx, authCode)
	if err != nil {
		returnStatus(w, http.StatusInternalServerError, "Failed to exchange token.")
		log.Fatal(err)
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		returnStatus(w, http.StatusInternalServerError, "No id_token field in OAuth 2.0 token.")
		log.Fatal(err)
	}

	// Verifying received ID token
	verifier := oidcProvider.Verifier(oidcConfig)
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		returnStatus(w, http.StatusInternalServerError, "Unable to verify ID token.")
		log.Fatal(err)
	}

	userInfo, err := oidcProvider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		log.Println("Problem fetching userinfo:", err.Error())
		returnStatus(w, http.StatusInternalServerError, "Not able to fetch userinfo.")
		return
	}

	claims := json.RawMessage{}
	if err = userInfo.Claims(&claims); err != nil {
		log.Println("Problem getting userinfo claims:", err.Error())
		returnStatus(w, http.StatusInternalServerError, "Not able to fetch userinfo claims.")
	}

	cookie := createSecureCookie(claims, idToken.Expiry, hostname)

	// Removing OIDC flow state from DB
	err = redisdb.Del(state).Err()
	if err != nil {
		log.Fatal(err)
	}

	// Hashing cookie value for key and saving claims to DB with it
	cookieHash := hashString(cookie.Value)
	err = redisdb.Set(cookieHash, string(claims[:]), time.Until(cookie.Expires)).Err()
	if err != nil {
		log.Println("Problem saving sessions claims:", err.Error())
		returnStatus(w, http.StatusInternalServerError, "Problem setting cookie.")
		return
	}

	log.Println("Login validated with ID token, redirecting with cookie.") // TODO add user from userinfo
	http.SetCookie(w, cookie)
	http.Redirect(w, r, destination, http.StatusFound)
}

// beginOIDCLogin starts the login sequence by creating state and forwarding user to OIDC provider for verification
func beginOIDCLogin(w http.ResponseWriter, r *http.Request, origURL string) {
	var state = createNonce(8)
	err := redisdb.Set(state, origURL, time.Hour).Err()
	if err != nil {
		panic(err)
	}

	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
}

func returnStatus(w http.ResponseWriter, statusCode int, errorMsg string) {
	w.WriteHeader(statusCode)
	w.Write([]byte(errorMsg))
}

func createSecureCookie(userinfo []byte, expiration time.Time, domain string) *http.Cookie {
	encoded, err := secCookie.Encode("userinfo", userinfo)
	if err != nil {
		panic(err)
	}

	cookie := &http.Cookie{
		Name:    "auth",
		Value:   encoded,
		Path:    "/",
		Domain:  domain,
		Expires: expiration,
	}

	return cookie
}

func createNonce(length int) string {
	var nonce = make([]rune, length)
	for i := range nonce {
		nonce[i] = nonceChars[rand.Intn(len(nonceChars))]
	}

	return string(nonce)
}

func getSecureValue(envVar string, expectedLength int) []byte {
	var envContent = os.Getenv(envVar)

	if len(envContent) == 0 {
		log.Println("Variable", envVar, "not defined, creating a random one.")
		return securecookie.GenerateRandomKey(expectedLength)
	}

	if len(envContent) < expectedLength {
		log.Println("WARNING: key", envVar, "smaller than expected length of", expectedLength)
	}

	return []byte(envContent)
}

func hashString(str string) string {
	hasher := md5.New()
	hasher.Write([]byte(str))
	return hex.EncodeToString(hasher.Sum(nil))
}
