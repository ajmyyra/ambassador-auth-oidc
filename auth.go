package main

import (
	"log"
	"math/rand"
	"net/http"
	"time"
)

var nonceChars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// AuthReqHandler processes all incoming requests
func AuthReqHandler(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Get("Authorization")) == 0 { // No auth header set
		log.Println("Authorization header missing, redirecting to login page.")
		redirectToLogin(w, r, r.Host+r.URL.Path)
	} else {
		log.Println("Authorization header found.")
		// TODO actually check the header..
		// add userinfo header and return 200 OK

		// TODO if actually correct, attach userinfo object as X-Auth-Userinfo header
		returnStatus(w, 200, "OK")
	}
}

// OIDCHandler processes AuthN responses from OpenID Provider, exchanges token to userinfo and establishes user session
func OIDCHandler(w http.ResponseWriter, r *http.Request) {
	authCode := r.FormValue("code")
	if len(authCode) == 0 {
		log.Println("Missing url parameter: code")
		returnStatus(w, 400, "Missing url parameter: code")
		return
	}

	state := r.FormValue("state")
	if len(state) == 0 {
		log.Println("Missing url parameter: state")
		returnStatus(w, 400, "Missing url parameter: state")
		return
	}

	destination, err := redisdb.Get(state).Result()
	if err != nil {
		if err.Error() == "redis: nil" { // State didn't exist, redirecting to new login
			log.Print("No state found with ", state, ", starting new auth session.\n")
			redirectToLogin(w, r, "/")
			return
		}

		// TODO This is not reached for some reason, just given empty response
		returnStatus(w, 500, "Error fetching state from DB.")
		panic(err)
	}

	log.Println("State found, would forward to", destination) //debug

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

	log.Println(rawIDToken)
	verifier := oidcProvider.Verifier(oidcConfig)
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		returnStatus(w, http.StatusInternalServerError, "Unable to verify ID token.")
		log.Fatal(err)
	}

	log.Println("Audience:", idToken.Audience)  //debug
	log.Println("Issuer:", idToken.Issuer)      //debug
	log.Println("Subject:", idToken.Subject)    //debug
	log.Println("Expiry:", idToken.Expiry)      //debug
	log.Println("Issued at:", idToken.IssuedAt) //debug

	// TODO fetch userinfo and either save to Redis or to JWT (if used)

	// TODO create token for user as JWT(?)
	// TODO return user token along with redirect to original resource (if possible?)

	err = redisdb.Del(state).Err()
	if err != nil {
		log.Fatal(err)
	}
}

func createNonce(length int) string {
	nonce := make([]rune, length)
	for i := range nonce {
		nonce[i] = nonceChars[rand.Intn(len(nonceChars))]
	}

	return string(nonce)
}

func redirectToLogin(w http.ResponseWriter, r *http.Request, origURL string) {
	state := createNonce(8)
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
