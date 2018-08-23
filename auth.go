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
		RedirectToLogin(w, r)
	} else {
		log.Println("Authorization header found.")
		// TODO return OK only for testing
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Debug OK!"))
	}
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
		// TODO return internal server error 500
	}
	return parsedURL.String()
}

// RedirectToLogin returns redirect to OAuth 2.0 login endpoint
func RedirectToLogin(w http.ResponseWriter, r *http.Request) {
	newNonce := createNonce(8)
	// TODO check for existing & save nonce to db for later checking

	redirectURL := strings.Join([]string{parseURL(os.Getenv("AUTH_URL")), "?response_type=code&client_id=", os.Getenv("CLIENT_ID"), "&redirect_uri=", parseURL(os.Getenv("SELF_URL")), "&scope=foo&state=", newNonce}, "")
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}
