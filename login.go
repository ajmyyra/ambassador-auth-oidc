package main

import (
	"context"
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
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

var ctx context.Context
var oauth2Config oauth2.Config
var oidcProvider *oidc.Provider
var oidcConfig *oidc.Config

var hmacSecret []byte
var nonceChars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func init() {
	hostname = strings.Split(parseEnvURL("SELF_URL").Host, ":")[0] // Because Host still has a port if it was in URL

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

	rand.Seed(time.Now().UnixNano())

	// 64 char(512 bit) key is needed for HS512
	hmacSecret = initialiseHMACSecretFromEnv("JWT_HMAC_SECRET", 64)
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
			log.Print(getUserIP(r), " No state found with ", state, ", starting new auth session.\n")
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

func createCookie(userinfo []byte, expiration time.Time, domain string) *http.Cookie {

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"jti": uuid.New().String(),
		"iss": hostname,
		"iat": time.Now().Unix(),
		"exp": expiration.Unix(),
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

func initialiseHMACSecretFromEnv(secEnv string, reqLen int) []byte {
	envContent := os.Getenv(secEnv)

	if len(envContent) < reqLen {
		log.Println("WARNING: HMAC secret not provided or secret too short. Generating a random one from nonce characters.")
		return []byte(createNonce(reqLen))
	}

	return []byte(envContent)
}
