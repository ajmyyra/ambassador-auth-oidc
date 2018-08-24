package main

import (
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// AuthReqHandler processes all incoming requests
func AuthReqHandler(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Get("Authorization")) == 0 { // No auth header set
		log.Println("Authorization header missing, redirecting to login page.")
		redirectToLogin(w, r)
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
	} // TODO execution does not end here, make it so.

	state := r.FormValue("state")
	if len(state) == 0 {
		log.Println("Missing url parameter: state")
		returnStatus(w, 400, "Missing url parameter: state")
	}

	log.Println("Received authcode", authCode, "with state", state) //debug

	destination, err := redisdb.Get(state).Result()
	if err != nil {
		panic(err)
	}

	log.Println("State found, would forward to", destination) //debug

	// TODO exchange code to userinfo with client id/secret
	// TODO create token for user and save it with userinfo
	// TODO return user token along with redirect to original resource
	// TODO remove used state
}

func createNonce(length int) string {
	nonce := make([]rune, length)
	for i := range nonce {
		nonce[i] = nonceChars[rand.Intn(len(nonceChars))]
	}

	return string(nonce)
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	state := createNonce(8)
	err := redisdb.Set(state, r.Host+r.URL.Path, time.Hour).Err()
	if err != nil {
		panic(err)
	}

	callbackURL := selfURL.String() + "/login/oidc"

	redirectURL := strings.Join([]string{authURL.String(), "?response_type=code&client_id=", clientID, "&redirect_uri=", callbackURL, "&scope=", strings.Replace(oidcScopes, " ", "%20", -1), "&state=", state}, "")
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func returnStatus(w http.ResponseWriter, statusCode int, errorMsg string) {
	w.WriteHeader(statusCode)
	w.Write([]byte(errorMsg))
}
