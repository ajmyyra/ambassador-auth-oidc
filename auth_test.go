package main

import (
	"testing"
	"time"
)

func TestBase64Functions(t *testing.T) {
	var testString = "2O/VY9uDc4Gb7ijn4Kxmmk8cOiLvpyBo93JpKL8HbBq9buWjULDOC2h8cG"
	encoded := base64encode([]byte(testString))
	decoded, err := base64decode(encoded)
	if err != nil {
		t.Error("Base64 decoding failed: " + err.Error())
	}

	if string(decoded[:]) != testString {
		t.Error("Teststring " + testString + " decoded back to something different: " + string(decoded[:]))
	}
}

func TestTokenBlacklisting(t *testing.T) {
	var testdomain = "testing.com"
	var userinfo = []byte("testfoo1234567890")
	var expiration = time.Now().Add(time.Hour)
	testJwt := createSignedJWT(userinfo, expiration)
	testCookie := createCookie(testJwt, expiration, testdomain)

	token, err := parseJWT(testCookie.Value)
	if err != nil {
		t.Error("Problem in JWT validation: " + err.Error())
	}

	tokenHash := hashString(token.Raw)
	if checkBlacklist(tokenHash) {
		t.Error("JWT hash in blacklist when it shouldn't.")
	}

	addToBlacklist(tokenHash, testCookie.Expires)
	if !checkBlacklist(tokenHash) {
		t.Error("JWT hash not in blacklist when it should.")
	}
}
