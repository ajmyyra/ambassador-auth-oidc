package main

import (
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var nonceChars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func init() {
	rand.Seed(time.Now().UnixNano())
}

// AuthReqHandler processes all incoming requests
func AuthReqHandler(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Get("Authorization")) == 0 { // No auth header set
		log.Println("Authorization header missing, redirecting to login page.")
		redirectToLogin(w, r)
	} else {
		log.Println("Authorization header found.")
		// TODO actually check the header..
		// add userinfo header and return 200 OK
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Debug OK!"))
	}
}

// OIDCHandler processes AuthN responses from OpenID Provider, exchanges token to userinfo and establishes user session
func OIDCHandler(w http.ResponseWriter, r *http.Request) {
	authCode := r.FormValue("code")
	state := r.FormValue("state")

	log.Println("Received authcode", authCode, "with state", state)
	// TODO check state from db & remove used state
	// TODO exchange code to userinfo with client id/secret
	// TODO create token for user and save it with userinfo
	// TODO return user token along with redirect to original resource
}

func createNonce(length int) string {
	nonce := make([]rune, length)
	for i := range nonce {
		nonce[i] = nonceChars[rand.Intn(len(nonceChars))]
	}

	return string(nonce)
}

func parseURL(rawURL string) string {
	parsedURL, err := url.ParseRequestURI(rawURL)
	if err != nil {
		log.Println("Not a valid URL:", rawURL)
		panic(err)
	}
	return parsedURL.String()
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	state := createNonce(8)
	// TODO check for existing & save state to db for later checking
	// TODO save full URL with state, key-value

	callbackURL := parseURL(os.Getenv("SELF_URL")) + "/login/oidc"

	redirectURL := strings.Join([]string{parseURL(os.Getenv("AUTH_URL")), "?response_type=code&client_id=", os.Getenv("CLIENT_ID"), "&redirect_uri=", callbackURL, "&scope=", strings.Replace(os.Getenv("OIDC_SCOPES"), " ", "%20", -1), "&state=", state}, "")
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func returnError(w http.ResponseWriter, errorCode int, errorMsg string) {
	w.WriteHeader(errorCode)
	w.Write([]byte(errorMsg))
}
