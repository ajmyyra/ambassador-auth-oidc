package main

import (
	"reflect"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

func TestNonceCreation(t *testing.T) {
	if len(createNonce(8)) != 8 {
		t.Error("Expected a nonce of 8 characters.")
	}
}

func TestCookieCreation(t *testing.T) {
	var testdomain = "testing.com"
	var userinfo = []byte("testfoo1234567890")
	var expiration = time.Now().Add(time.Hour)
	testJwt := createSignedJWT(userinfo, expiration)
	testCookie := createCookie(testJwt, expiration, testdomain)

	if testCookie.Domain != testdomain {
		t.Error("Expected cookie domain to be " + testdomain + ", got " + testCookie.Domain + "instead.")
	}

	if !testCookie.Expires.Equal(expiration) {
		t.Error("Expiration time different from given time: " + testCookie.Expires.String())
	}

	cookieJWT, err := parseJWT(testCookie.Value)
	if err != nil {
		t.Error("Problem in JWT validation: " + err.Error())
	}

	uifClaim, err := base64decode(cookieJWT.Claims.(jwt.MapClaims)["uif"].(string))
	if err != nil {
		t.Error("Trouble getting uif claim from JWT: " + err.Error())
	}

	if !reflect.DeepEqual(userinfo, uifClaim) {
		t.Error("Userinfo different from uif claim. Userinfo: " + string(userinfo[:]) + ", uif claim: " + string(uifClaim[:]))
	}
}

// TODO mock OIDC endpoint and test different scenarios.
