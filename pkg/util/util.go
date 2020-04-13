package util

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
)

var nonceChars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func ReturnStatus(w http.ResponseWriter, statusCode int, errorMsg string) {
	w.WriteHeader(statusCode)
	w.Write([]byte(errorMsg))
}

func GetUserIP(r *http.Request) string {
	headerIP := r.Header.Get("X-Forwarded-For")
	if headerIP != "" {
		return headerIP
	}

	return strings.Split(r.RemoteAddr, ":")[0]
}

func HashString(str string) string {
	hasher := md5.New()
	hasher.Write([]byte(str))
	return hex.EncodeToString(hasher.Sum(nil))
}

func Base64decode(str string) ([]byte, error) {
	arr, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}

	return arr, nil
}

func Base64encode(data []byte) string {
	str := base64.StdEncoding.EncodeToString(data)
	return str
}

func CreateNonce(length int) string {
	var nonce = make([]rune, length)
	for i := range nonce {
		nonce[i] = nonceChars[rand.Intn(len(nonceChars))]
	}

	return string(nonce)
}

func InitialiseHMACSecretFromEnv(secEnv string, reqLen int) []byte {
	envContent := os.Getenv(secEnv)

	if len(envContent) < reqLen {
		log.Println("WARNING: HMAC secret not provided or secret too short. Generating a random one from nonce characters.")
		return []byte(CreateNonce(reqLen))
	}

	return []byte(envContent)
}