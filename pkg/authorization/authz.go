package authorization

import (
	"github.com/ajmyyra/ambassador-auth-oidc/pkg/authentication"
	"github.com/ajmyyra/ambassador-auth-oidc/pkg/persistence"
	"github.com/ajmyyra/ambassador-auth-oidc/pkg/util"
	"log"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type AuthZConfig struct {
	Whitelist []string
}


func NewDefaultConfig(whitelist []string) AuthZConfig {
	return AuthZConfig{
		Whitelist:    whitelist,
	}
}

type AuthZController struct {
	config AuthZConfig
	authN *authentication.AuthNController
	keystore *persistence.Keystore
}

func New(config AuthZConfig, authNControl *authentication.AuthNController, keystore *persistence.Keystore) (AuthZController, error) {
	controller := AuthZController{
		config: config,
		authN: authNControl,
		keystore:  keystore,
	}

	return controller, nil
}

// AuthReqHandler processes all incoming requests by default, unless specific endpoint is mentioned
func (s *AuthZController) AuthReqHandler(w http.ResponseWriter, r *http.Request) {
	var userToken string

	if len(s.config.Whitelist) > 0 {
		for _, v := range s.config.Whitelist {
			if strings.HasPrefix(r.URL.String(), string(v)) {
				log.Println(util.GetUserIP(r), r.URL.String(), "URI is whitelisted. Accepted without authorization.")
				util.ReturnStatus(w, http.StatusOK, "OK")
				return
			}
		}
	}
	if len(r.Header.Get("X-Auth-Token")) != 0 { // Header available in request
		userToken = r.Header.Get("X-Auth-Token")
	} else {
		cookie, err := r.Cookie("auth")
		if err != nil {
			log.Println(util.GetUserIP(r), r.URL.String(), "Cookie not set, redirecting to login.")
			s.authN.BeginOIDCLogin(w, r, r.URL.Path)
			return
		}
		userToken = cookie.Value
	}

	deletionCookie := authentication.CreateCookie("", time.Now().AddDate(0, 0, -2), s.authN.GetHostname())

	if len(userToken) == 0 { // Cookie or auth header empty
		log.Println(util.GetUserIP(r), r.URL.String(), "Empty authorization header.")
		http.SetCookie(w, deletionCookie)
		s.authN.BeginOIDCLogin(w, r, r.URL.Path)
		return
	}

	token, err := s.authN.ParseAndValidateJWT(userToken)
	if err != nil {
		if err.Error() == "Token is expired" {
			w.Header().Set("X-Unauthorized-Reason", "Token Expired")
			log.Println(util.GetUserIP(r), r.URL.String(), "JWT token expired.")
		} else {
			log.Println(util.GetUserIP(r), r.URL.String(), "Problem validating JWT:", err.Error())
		}

		http.SetCookie(w, deletionCookie)
		s.authN.BeginOIDCLogin(w, r, r.URL.Path)
		util.ReturnStatus(w, http.StatusUnauthorized, "Cookie/header expired or malformed.")
		return
	}

	if s.keystore.CheckBlacklist(token.Raw) {
		log.Println(util.GetUserIP(r), r.URL.String(), "Token in blacklist.")
		http.SetCookie(w, deletionCookie)
		s.authN.BeginOIDCLogin(w, r, r.URL.Path)
		return
	}

	uifClaim, err := util.Base64decode(token.Claims.(jwt.MapClaims)["uif"].(string))
	if err != nil {
		log.Println(util.GetUserIP(r), r.URL.String(), "Not able to decode base64 content:", err.Error())
		http.SetCookie(w, deletionCookie)
		s.authN.BeginOIDCLogin(w, r, r.URL.Path)
		return
	}

	log.Println(util.GetUserIP(r), r.URL.String(), "Authorized & accepted.")
	w.Header().Set("X-Auth-Userinfo", string(uifClaim[:]))
	util.ReturnStatus(w, http.StatusOK, "OK")
}


