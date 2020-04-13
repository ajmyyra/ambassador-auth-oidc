package persistence

import (
	"github.com/ajmyyra/ambassador-auth-oidc/pkg/util"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"testing"
	"time"
)

var testJWTSecret = []byte("BpLnfgDsc2WD8F2qNfHK5a84jjJkwzDkh9h2fhfUVuS9jZ8uVbhV3vC5AWX39IVU")

func newTestKeystore() Keystore {
	keystore, err := New("", "")
	if err != nil {
		panic(err)
	}

	return keystore
}

func newTestRedisKeystore() Keystore {
	// TODO setup Redis mocking for this
	return Keystore{}
}

func newTestJWT(userInfoText []byte) *jwt.Token {
	issuedAt := time.Now().Unix()
	expires := time.Now().Add(2 * time.Duration(time.Hour)).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"jti": uuid.New().String(),
		"iss": "http://test.example.com",
		"iat": issuedAt,
		"exp": expires,
		"uif": util.Base64encode(userInfoText),
	})

	return token
}

func keystoreTests(ks Keystore) {
	// TODO tests for external keystore functions
}

func TestRedisKeystore(t *testing.T) {
	// TODO run keystore tests against Redis-backed keystore
}

func TestInternalKeystore(t *testing.T) {
	// TODO run keystore tests against keystore without Redis
}

func TestTokenBlacklisting(t *testing.T) {
	ks := newTestKeystore()

	testTokenUif := []byte("testuserinfo")
	testToken := newTestJWT(testTokenUif)
	testTokenString, err := testToken.SignedString(testJWTSecret)
	if err != nil {
		t.Error("Unable to get test token string: " + err.Error())
	}

	tokenHash := util.HashString(testTokenString)
	if ks.CheckBlacklist(tokenHash) {
		t.Error("JWT hash in blacklist when it shouldn't.")
	}

	ks.AddToBlacklist(tokenHash, time.Now().Add(2 * time.Duration(time.Hour)))
	if !ks.CheckBlacklist(tokenHash) {
		t.Error("JWT hash not in blacklist when it should.")
	}
}