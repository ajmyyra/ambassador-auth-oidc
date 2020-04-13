package authentication

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ajmyyra/ambassador-auth-oidc/pkg/persistence"
	"github.com/ajmyyra/ambassador-auth-oidc/pkg/util"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type AuthNConfig struct {
	SelfAddress url.URL
	OIDCProvider url.URL
	OIDCScopes []string
	ClientId string
	ClientSecret string
	JWTSecret []byte
	UserInfo bool
	LogoutCookie bool
}

type OIDCEndpoint struct {
	provider oidc.Provider
	oidcConfig oidc.Config
	oAuthConfig oauth2.Config
	scopes []string
	ctx context.Context
}

type AuthNController struct {
	config   AuthNConfig
	keystore *persistence.Keystore
	oidc OIDCEndpoint
}

func New(config AuthNConfig, keys *persistence.Keystore) (AuthNController, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, config.OIDCProvider.String())
	if err != nil {
		return AuthNController{}, errors.Wrap(err, "OIDC provider setup failed")
	}
	OIDCConfig := oidc.Config{
		ClientID: config.ClientId,
	}

	redirURL := config.SelfAddress.String() + "/login/oidc"

	oauth2Config := oauth2.Config{
		ClientID:     config.ClientId,
		ClientSecret: config.ClientSecret,
		RedirectURL:  redirURL,
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		Scopes: config.OIDCScopes,
	}

	endpoint := OIDCEndpoint{
		provider: *provider,
		oidcConfig:   OIDCConfig,
		oAuthConfig: oauth2Config,
		scopes:   config.OIDCScopes,
		ctx: ctx,
	}

	return AuthNController{
		config:   config,
		oidc: endpoint,
		keystore: keys,
	}, nil
}

// OIDCHandler processes authn responses from OpenID Provider, exchanges token to
// userinfo and establishes user session with cookie containing the created  JWT token.
func (s *AuthNController) OIDCHandler(w http.ResponseWriter, r *http.Request) {
	var authCode = r.FormValue("code")
	if len(authCode) == 0 {
		log.Println(util.GetUserIP(r), "Missing url parameter: code")
		util.ReturnStatus(w, http.StatusBadRequest, "Missing url parameter: code")
		return
	}

	var state = r.FormValue("state")
	if len(state) == 0 {
		log.Println(util.GetUserIP(r), "Missing url parameter: state")
		util.ReturnStatus(w, http.StatusBadRequest, "Missing url parameter: state")
		return
	}

	// Getting original destination if it exists
	session, err := s.keystore.FindLoginSession(state)
	if err != nil {
		log.Println(util.GetUserIP(r), "Fetching the session failed.")
		util.ReturnStatus(w, http.StatusInternalServerError, "Error fetching state from DB.")
		return
	}

	if session == nil {
		log.Print(util.GetUserIP(r), " No state found with ", state, ", starting new auth session.\n")
		s.BeginOIDCLogin(w, r, "/")
		return
	}

	oauth2Token, err := s.oidc.oAuthConfig.Exchange(s.oidc.ctx, authCode)
	if err != nil {
		log.Println("Failed to exchange token:", err.Error())
		util.ReturnStatus(w, http.StatusInternalServerError, "Failed to exchange token.")
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Println("No id_token field available.")
		util.ReturnStatus(w, http.StatusInternalServerError, "No id_token field in OAuth 2.0 token.")
		return
	}

	// Verifying received ID token
	verifier := s.oidc.provider.Verifier(&s.oidc.oidcConfig)
	idToken, err := verifier.Verify(s.oidc.ctx, rawIDToken)
	if err != nil {
		log.Println("Not able to verify ID token:", err.Error())
		util.ReturnStatus(w, http.StatusInternalServerError, "Unable to verify ID token.")
		return
	}

	claims := json.RawMessage{}
	if s.config.UserInfo {
		userInfo, err := s.oidc.provider.UserInfo(s.oidc.ctx, oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			log.Println("Problem fetching userinfo:", err.Error())
			util.ReturnStatus(w, http.StatusInternalServerError, "Not able to fetch userinfo.")
			return
		}

		if err = userInfo.Claims(&claims); err != nil {
			log.Println("Problem getting userinfo claims:", err.Error())
			util.ReturnStatus(w, http.StatusInternalServerError, "Not able to fetch userinfo claims.")
			return
		}
	} else {
		if err = idToken.Claims(&claims); err != nil {
			log.Println("Problem getting id_token claims:", err.Error())
			util.ReturnStatus(w, http.StatusInternalServerError, "Not able to fetch id_token claims.")
			return
		}
	}

	userJwt := s.createSignedJWT(claims, idToken.Expiry)
	cookie := CreateCookie(userJwt, idToken.Expiry, s.GetHostname())

	// Removing OIDC flow state from DB
	s.keystore.RemoveLoginSession(state)

	log.Println(util.GetUserIP(r), "Login validated with ID token, redirecting with JWT cookie.")
	http.SetCookie(w, cookie)
	http.Redirect(w, r, session.OrigURL, http.StatusFound)
}

// BeginOIDCLogin starts the login sequence by creating state and forwarding user to OIDC provider for verification
func (s *AuthNController) BeginOIDCLogin(w http.ResponseWriter, r *http.Request, origURL string) {
	state, err := s.keystore.CreateLoginSession(origURL)
	if err != nil {
		panic(err) // TODO handle more gracefully & return error
	}

	http.Redirect(w, r, s.oidc.oAuthConfig.AuthCodeURL(state), http.StatusFound)
}

// LogoutSession blacklists user token
func (s *AuthNController) LogoutSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("auth")
	if err != nil {
		log.Println(util.GetUserIP(r), r.URL.String(), "Cookie not set, not able to logout.")
		util.ReturnStatus(w, http.StatusBadRequest, "Cookie not set.")
		return
	}

	token, err := s.ParseAndValidateJWT(cookie.Value)
	if err != nil {
		log.Println(util.GetUserIP(r), r.URL.String(), "Not able to use JWT:", err.Error())
		util.ReturnStatus(w, http.StatusBadRequest, "Malformed JWT in cookie.")
		return
	}

	if s.keystore.CheckBlacklist(token.Raw) {
		log.Println(util.GetUserIP(r), r.URL.String(), "Token already blacklisted, cannot to logout again.")
		util.ReturnStatus(w, http.StatusForbidden, "Not logged in.")
		return
	}

	jwtExp := int64(token.Claims.(jwt.MapClaims)["exp"].(float64))

	if _, err = s.keystore.AddToBlacklist(token.Raw, time.Unix(jwtExp, 0)); err != nil {
		log.Println(util.GetUserIP(r), "Problem setting JWT to Redis blacklist:", err.Error())
		util.ReturnStatus(w, http.StatusInternalServerError, "Problem logging out.")
		return
	}

	log.Println(util.GetUserIP(r), r.URL.String(), "Logged out, token added to blacklist.")

	if s.config.LogoutCookie { // Sends empty expired cookie to remove the logged out one.
		newCookie := CreateCookie("", time.Now().AddDate(0, 0, -2), s.GetHostname())
		http.SetCookie(w, newCookie)
	}

	util.ReturnStatus(w, http.StatusOK, "Succesfully logged out.")
}

func CreateCookie(sessionJwt string, expiration time.Time, domain string) *http.Cookie {

	cookie := &http.Cookie{
		Name:    "auth",
		Value:   sessionJwt,
		Path:    "/",
		Domain:  domain,
		Expires: expiration,
	}

	return cookie
}

func (s *AuthNController) createSignedJWT(userinfo []byte, expiration time.Time) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"jti": uuid.New().String(),
		"iss": s.config.SelfAddress.String(),
		"iat": time.Now().Unix(),
		"exp": expiration.Unix(),
		"uif": util.Base64encode(userinfo), // Userinfo will be readable to user
	})

	tokenString, err := token.SignedString(s.config.JWTSecret)
	if err != nil {
		panic(err)
	}

	return tokenString
}

func (s *AuthNController) ParseAndValidateJWT(tokenstr string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenstr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return s.config.JWTSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if token.Valid {
		return token, nil
	}

	return nil, errors.New("Invalid token")
}

func (s *AuthNController) GetHostname() string {
	return strings.Split(s.config.SelfAddress.Host, ":")[0]
}

