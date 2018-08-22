package main

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

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

func getURL(rawURL string) *url.URL {
	parsedURL, err := url.ParseRequestURI(rawURL)
	if err != nil {
		panic(err)
	}
	return parsedURL
}

// RedirectToLogin returns redirect to OAuth 2.0 login endpoint
func RedirectToLogin(w http.ResponseWriter, r *http.Request) {
	redirectURL := strings.Join([]string{os.Getenv("AUTH_URL"), "?response_type=code&client_id=", os.Getenv("CLIENT_ID"), "&redirect_uri=", os.Getenv("SELF_URL"), "&scope=foo&state=bar"}, "")
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}
