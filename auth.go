package main

import (
	"crypto/md5"
	"encoding/hex"
	"log"
	"math/rand"
	"net/http"
	"os"
	"reflect"
	"time"

	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

var nonceChars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
var secCookie *securecookie.SecureCookie

func init() {

	var hashKey = getSecureValue("SEC_HASHKEY", 64)
	var blockKey = getSecureValue("SEC_BLOCKKEY", 32)
	secCookie = securecookie.New(hashKey, blockKey)
}

// LoginHandler processes login requests
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	beginOIDCLogin(w, r, "/")
}

// AuthReqHandler processes all incoming requests
func AuthReqHandler(w http.ResponseWriter, r *http.Request) {
	// TODO CORS check, others?

	cookie, err := r.Cookie("auth")
	if err != nil {
		log.Println("Cookie not set, redirecting to login.")
		beginOIDCLogin(w, r, r.Host+r.URL.Path)
		return
	}

	if len(cookie.Value) == 0 { // No auth header set
		log.Println("Empty authorization header, returning error 400.")
		returnStatus(w, http.StatusBadRequest, "Cookie empty or malformed.")
	} else { // TODO actually validate the securecookie

		// For securecookie validation
		// log.Println("Decoded:")
		// var value []byte
		// secCookie.Decode("userinfo", cookie.Value, &value)
		// log.Println(string(value[:]))

		log.Println("Authorization header found.") //debug
		cookieHash := hashString(cookie.Value)

		userInfoClaims, err := redisdb.Get(cookieHash).Result()
		if err != nil {
			log.Println("Session not found for", cookieHash)
			returnStatus(w, http.StatusForbidden, "Session not found.")
			return
		}

		if cookie.Expires.After(time.Now()) {
			log.Println("Session in DB, but has expired:", cookieHash)
			returnStatus(w, http.StatusForbidden, "Session has expired.")
			return
		}

		w.Header().Set("X-Auth-Userinfo", userInfoClaims)
		returnStatus(w, 200, "OK")
	}
}

// OIDCHandler processes AuthN responses from OpenID Provider, exchanges token to userinfo and establishes user session
func OIDCHandler(w http.ResponseWriter, r *http.Request) {
	var authCode = r.FormValue("code")
	if len(authCode) == 0 {
		log.Println("Missing url parameter: code")
		returnStatus(w, 400, "Missing url parameter: code")
		return
	}

	var state = r.FormValue("state")
	if len(state) == 0 {
		log.Println("Missing url parameter: state")
		returnStatus(w, 400, "Missing url parameter: state")
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

		// TODO This is not reached for some reason, just given empty response
		returnStatus(w, 500, "Error fetching state from DB.")
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
		returnStatus(w, 500, "Not able to fetch userinfo.")
		return
	}

	u := reflect.ValueOf(userInfo)
	claims := reflect.Indirect(u).FieldByName("claims").Bytes() // Userinfo claims

	cookie := createSecureCookie(claims, idToken.Expiry, hostname)

	// Removing OIDC flow state from DB
	err = redisdb.Del(state).Err()
	if err != nil {
		log.Fatal(err)
	}

	// Hashing cookie value for key and saving claims to DB with it
	cookieHash := hashString(cookie.Value)
	err = redisdb.Set(cookieHash, claims, time.Until(cookie.Expires)).Err()
	if err != nil {
		log.Println("Problem saving sessions claims:", err.Error())
		returnStatus(w, 500, "Problem setting cookie.")
		return
	}

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
