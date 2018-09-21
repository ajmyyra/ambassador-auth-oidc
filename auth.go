package main

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

var hostname string
var redisdb *redis.Client
var ctx context.Context
var oauth2Config oauth2.Config
var oidcProvider *oidc.Provider
var oidcConfig *oidc.Config

var nonceChars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
var hmacSecret []byte

var blacklist []string

func init() {
	hostname = strings.Split(parseEnvURL("SELF_URL").Host, ":")[0] // Because Host still has a port if it was in URL

	redisAddr := parseEnvVar("REDIS_ADDRESS")
	redisPwd := parseEnvVar("REDIS_PASSWORD")
	redisdb = redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPwd,
		DB:       0,
	})

	_, err := redisdb.Ping().Result()
	if err != nil {
		log.Fatal("Problem connecting to Redis: ", err.Error())
	}

	rand.Seed(time.Now().UnixNano())

	clientID := parseEnvVar("CLIENT_ID")
	clientSecret := parseEnvVar("CLIENT_SECRET")

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

	// 64 char(512 bit) key is needed for HS512
	hmacSecret = initialiseHMACSecretFromEnv("JWT_HMAC_SECRET", 64)
}

// LoginHandler processes login requests
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	beginOIDCLogin(w, r, "/")
}

// LogoutHandler blacklists user token
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	//TODO
}

// Wildcardhandler to provide ServeHTTP method required for Go's handlers
type wildcardHandler struct {
}

func (wh *wildcardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	AuthReqHandler(w, r)
}

func newWildcardHandler() *wildcardHandler {
	return &wildcardHandler{}
}

// AuthReqHandler processes all incoming requests by default, unless specific endpoint is mentioned
func AuthReqHandler(w http.ResponseWriter, r *http.Request) {
	// TODO CORS check, others?
	// TODO add user from userinfo to logs

	cookie, err := r.Cookie("auth")
	if err != nil {
		log.Println(getUserIP(r), r.URL.String(), "Cookie not set, redirecting to login.")
		beginOIDCLogin(w, r, r.URL.Path)
		return
	}

	if len(cookie.Value) == 0 { // No auth header set
		log.Println(getUserIP(r), r.URL.String(), "Empty authorization header.")
		returnStatus(w, http.StatusBadRequest, "Cookie empty or malformed.")
	} else {
		// TODO check JWT validation and ditch Redis

		token, err := parseJWT(cookie.Value)
		if err != nil {

			// TODO if expired, add X-Unauthorised-Reason
			if err.Error() == "Token is expired" {
				w.Header().Set("X-Unauthorized-Reason", "Token Expired")
				log.Println(getUserIP(r), r.URL.String(), "JWT token expired.")
			} else {
				log.Println(getUserIP(r), r.URL.String(), "Problem validating JWT:", err.Error())
			}

			returnStatus(w, http.StatusUnauthorized, "Malformed or expired token in cookie.")
			return
		}

		uifClaim, err := base64decode(getJWTClaimString(token, "uif"))
		if err != nil {
			log.Println(getUserIP(r), r.URL.String(), "Not able to decode base64 content:", err.Error())
			returnStatus(w, http.StatusBadRequest, "Malformed cookie.")
			return
		}

		cookieHash := hashString(cookie.Value)

		userInfoClaims, err := redisdb.Get("cookie-" + cookieHash).Result()
		if err != nil {
			log.Println(getUserIP(r), r.URL.String(), "Session not found for", cookieHash)
			returnStatus(w, http.StatusForbidden, "Session not found.")
			return
		}

		if strings.Compare(string(uifClaim[:]), userInfoClaims) == 0 {
			log.Println(getUserIP(r), r.URL.String(), "Accepted")
			w.Header().Set("X-Auth-Userinfo", userInfoClaims)
			returnStatus(w, http.StatusOK, "OK")
		} else {
			log.Println(getUserIP(r), r.URL.String(), "Cookie validation failed, cookie and DB differ.")
			returnStatus(w, http.StatusForbidden, "Incorrect cookie.")
		}
	}
}

// OIDCHandler processes authn responses from OpenID Provider, exchanges token to userinfo and establishes user session with cookie containing JWT token
func OIDCHandler(w http.ResponseWriter, r *http.Request) {
	var authCode = r.FormValue("code")
	if len(authCode) == 0 {
		log.Println(getUserIP(r), "Missing url parameter: code")
		returnStatus(w, http.StatusBadRequest, "Missing url parameter: code")
		return
	}

	var state = r.FormValue("state")
	if len(state) == 0 {
		log.Println(getUserIP(r), "Missing url parameter: state")
		returnStatus(w, http.StatusBadRequest, "Missing url parameter: state")
		return
	}

	// Getting original destination from DB with state
	destination, err := redisdb.Get("state-" + state).Result()
	if err != nil {
		if err.Error() == "redis: nil" { // State didn't exist, redirecting to new login
			log.Print(getUserIP(r), "No state found with ", state, ", starting new auth session.\n")
			beginOIDCLogin(w, r, "/")
			return
		}

		returnStatus(w, http.StatusInternalServerError, "Error fetching state from DB.")
		panic(err)
	}

	oauth2Token, err := oauth2Config.Exchange(ctx, authCode)
	if err != nil {
		log.Println("Failed to exchange token:", err.Error())
		returnStatus(w, http.StatusInternalServerError, "Failed to exchange token.")
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Println("No id_token field available.")
		returnStatus(w, http.StatusInternalServerError, "No id_token field in OAuth 2.0 token.")
		return
	}

	// Verifying received ID token
	verifier := oidcProvider.Verifier(oidcConfig)
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Println("Not able to verify ID token:", err.Error())
		returnStatus(w, http.StatusInternalServerError, "Unable to verify ID token.")
		return
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
		return
	}

	cookie := createCookie(claims, idToken.Expiry, hostname)

	// Removing OIDC flow state from DB
	err = redisdb.Del("state-" + state).Err()
	if err != nil {
		log.Println("WARNING: Unable to remove state from DB,", err.Error())
	}

	// Hashing cookie value for key and saving claims to DB with it
	cookieHash := hashString(cookie.Value)
	err = redisdb.Set("cookie-"+cookieHash, string(claims[:]), time.Until(cookie.Expires)).Err()
	if err != nil {
		log.Println("Problem saving sessions claims:", err.Error())
		returnStatus(w, http.StatusInternalServerError, "Problem setting cookie.")
		return
	}

	log.Println(getUserIP(r), "Login validated with ID token, redirecting with cookie.") // TODO add user from userinfo
	http.SetCookie(w, cookie)
	http.Redirect(w, r, destination, http.StatusFound)
}

// beginOIDCLogin starts the login sequence by creating state and forwarding user to OIDC provider for verification
func beginOIDCLogin(w http.ResponseWriter, r *http.Request, origURL string) {
	var state = createNonce(8)
	err := redisdb.Set("state-"+state, origURL, time.Hour).Err()
	if err != nil {
		panic(err)
	}

	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
}

func returnStatus(w http.ResponseWriter, statusCode int, errorMsg string) {
	w.WriteHeader(statusCode)
	w.Write([]byte(errorMsg))
}

func createCookie(userinfo []byte, expiration time.Time, domain string) *http.Cookie {

	newExpiration := time.Now().Add(time.Minute * time.Duration(1)) // REMOVE

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"jti": uuid.New().String(),
		"iss": hostname,
		"iat": time.Now().Unix(),
		"exp": newExpiration.Unix(),
		"uif": base64encode(userinfo), // Userinfo will be readable to user
	})

	tokenString, err := token.SignedString(hmacSecret)
	if err != nil {
		panic(err)
	}

	cookie := &http.Cookie{
		Name:    "auth",
		Value:   tokenString,
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

func parseJWT(tokenstr string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenstr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return hmacSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if token.Valid {
		return token, nil
	}

	return nil, errors.New("Token not valid")
}

func getJWTClaimString(token *jwt.Token, claim string) string {
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims[claim].(string)
	}

	return ""
}

func getUserIP(r *http.Request) string {
	headerIP := r.Header.Get("X-Forwarded-For")
	if headerIP != "" {
		return headerIP
	}

	return strings.Split(r.RemoteAddr, ":")[0]
}

func hashString(str string) string {
	hasher := md5.New()
	hasher.Write([]byte(str))
	return hex.EncodeToString(hasher.Sum(nil))
}

func base64encode(data []byte) string {
	str := base64.StdEncoding.EncodeToString(data)
	return str
}

func base64decode(str string) ([]byte, error) {
	arr, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}

	return arr, nil
}

func initialiseHMACSecretFromEnv(secEnv string, reqLen int) []byte {
	envContent := os.Getenv(secEnv)

	if len(envContent) < reqLen {
		log.Println("WARNING: HMAC secret not provided or secret too short. Generating a random one from nonce characters.")
		return []byte(createNonce(reqLen))
	}

	return []byte(envContent)
}
