package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
)

var hostname string

var redisdb *redis.Client

var logoutCookie = false
var disableUserInfo = false

var whitelist []string
var blacklist []string // TODO Refactor to struct with expiration time, and add cleaner.

type blacklistItem struct {
	Key        string    `json:"key"`
	JWTHash    string    `json:"hash"`
	Expiration time.Time `json:"exp"`
}

func init() {
	redisAddr := getenvOrDefault("REDIS_ADDRESS", "")
	redisPwd := getenvOrDefault("REDIS_PASSWORD", "")

	if redisAddr != "" {
		redisdb = redis.NewClient(&redis.Options{
			Addr:     redisAddr,
			Password: redisPwd,
			DB:       0,
		})

		_, err := redisdb.Ping().Result()
		if err != nil {
			log.Fatal("Problem connecting to Redis: ", err.Error())
		}

		log.Println("Using Redis at", redisAddr)
	} else {
		log.Println("No Redis address specified, storing items locally.")
		redisdb = nil
	}

	whitelist = strings.Split(getenvOrDefault("SKIP_AUTH_URI", ""), " ")
	if len(whitelist[0]) > 0 {
		log.Println("Skipping authorization for URIs:", whitelist)
	}

	envContent := os.Getenv("LOGOUT_COOKIE")
	if envContent == "true" {
		logoutCookie = true
	}

	envContent = os.Getenv("DISABLE_USERINFO")
	if envContent == "true" {
		disableUserInfo = true
	}
}

// LoginHandler processes login requests
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	beginOIDCLogin(w, r, "/")
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
	var userToken string

	if len(whitelist[0]) > 0 {
		for _, v := range whitelist {
			if strings.HasPrefix(r.URL.String(), string(v)) {
				log.Println(getUserIP(r), r.URL.String(), "URI is whitelisted. Accepted without authorization.")
				returnStatus(w, http.StatusOK, "OK")
				return
			}
		}
	}
	if len(r.Header.Get("X-Auth-Token")) != 0 { // Header available in request
		userToken = r.Header.Get("X-Auth-Token")
	} else {
		cookie, err := r.Cookie("auth")
		if err != nil {
			log.Println(getUserIP(r), r.URL.String(), "Cookie not set, redirecting to login.")
			beginOIDCLogin(w, r, r.URL.Path)
			return
		}
		userToken = cookie.Value
	}

	deletionCookie := createCookie("", time.Now().AddDate(0, 0, -2), hostname)

	if len(userToken) == 0 { // Cookie or auth header empty
		log.Println(getUserIP(r), r.URL.String(), "Empty authorization header.")
		http.SetCookie(w, deletionCookie)
		beginOIDCLogin(w, r, r.URL.Path)
		return
	}

	token, err := parseJWT(userToken)
	if err != nil {
		if err.Error() == "Token is expired" {
			w.Header().Set("X-Unauthorized-Reason", "Token Expired")
			log.Println(getUserIP(r), r.URL.String(), "JWT token expired.")
		} else {
			log.Println(getUserIP(r), r.URL.String(), "Problem validating JWT:", err.Error())
		}

		http.SetCookie(w, deletionCookie)
		beginOIDCLogin(w, r, r.URL.Path)
		returnStatus(w, http.StatusUnauthorized, "Cookie/header expired or malformed.")
		return
	}

	if checkBlacklist(hashString(token.Raw)) {
		log.Println(getUserIP(r), r.URL.String(), "Token in blacklist.")
		http.SetCookie(w, deletionCookie)
		beginOIDCLogin(w, r, r.URL.Path)
		return
	}

	uifClaim, err := base64decode(token.Claims.(jwt.MapClaims)["uif"].(string))
	if err != nil {
		log.Println(getUserIP(r), r.URL.String(), "Not able to decode base64 content:", err.Error())
		http.SetCookie(w, deletionCookie)
		beginOIDCLogin(w, r, r.URL.Path)
		return
	}

	log.Println(getUserIP(r), r.URL.String(), "Authorized & accepted.")
	w.Header().Set("X-Auth-Userinfo", string(uifClaim[:]))
	returnStatus(w, http.StatusOK, "OK")
}

// LogoutHandler blacklists user token
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("auth")
	if err != nil {
		log.Println(getUserIP(r), r.URL.String(), "Cookie not set, not able to logout.")
		returnStatus(w, http.StatusBadRequest, "Cookie not set.")
		return
	}

	token, err := parseJWT(cookie.Value)
	if err != nil {
		log.Println(getUserIP(r), r.URL.String(), "Not able to use JWT:", err.Error())
		returnStatus(w, http.StatusBadRequest, "Malformed JWT in cookie.")
		return
	}

	tokenHash := hashString(token.Raw)
	if checkBlacklist(tokenHash) {
		log.Println(getUserIP(r), r.URL.String(), "Token already blacklisted, cannot to logout again.")
		returnStatus(w, http.StatusForbidden, "Not logged in.")
		return
	}

	jwtExp := int64(token.Claims.(jwt.MapClaims)["exp"].(float64))

	_, err = addToBlacklist(tokenHash, time.Unix(jwtExp, 0))
	if err != nil {
		log.Println(getUserIP(r), "Problem setting JWT to Redis blacklist:", err.Error())
		returnStatus(w, http.StatusInternalServerError, "Problem logging out.")
		return
	}

	log.Println(getUserIP(r), r.URL.String(), "Logged out, token added to blacklist.")

	if logoutCookie { // Sends empty expired cookie to remove the logged out one.
		newCookie := createCookie("", time.Now().AddDate(0, 0, -2), hostname)
		http.SetCookie(w, newCookie)
	}

	// redirect to login page
	beginOIDCLogin(w, r, r.URL.Path)
}

func returnStatus(w http.ResponseWriter, statusCode int, errorMsg string) {
	w.WriteHeader(statusCode)
	w.Write([]byte(errorMsg))
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

func addToBlacklist(tokenHash string, exp time.Time) (bool, error) {
	blKey := createNonce(8)
	blItem := &blacklistItem{Key: blKey, JWTHash: tokenHash, Expiration: exp}

	if redisdb != nil {
		blJSON, err := json.Marshal(blItem)
		if err != nil {
			panic(err)
		}

		err = redisdb.HSet("blacklist", blKey, string(blJSON)).Err()
		if err != nil {
			return false, err
		}
	}

	blacklist = append(blacklist, tokenHash)
	return true, nil
}

func updateBlacklist() {
	res, err := redisdb.HVals("blacklist").Result()
	if err != nil {
		panic(err)
	}

	var newBlacklist []string

	for _, i := range res {
		var blItem blacklistItem

		err = json.Unmarshal([]byte(i), &blItem)
		if err != nil {
			panic(err)
		}

		if blItem.Expiration.Before(time.Now()) {
			log.Println("Removing expired token", blItem.Key, "from blacklist.")
			err = redisdb.HDel("blacklist", blItem.Key).Err()
			if err != nil {
				panic(err)
			}
			continue
		}

		newBlacklist = append(newBlacklist, blItem.JWTHash)
	}

	if !reflect.DeepEqual(blacklist, newBlacklist) {
		blacklist = newBlacklist
		log.Println("Blacklist changes in Redis, local blacklist recreated.")
	}

}

func checkBlacklist(jwtHash string) bool {
	for _, elem := range blacklist {
		if jwtHash == elem {
			return true
		}
	}

	return false
}
