package util

import (
	"testing"
)

func TestBase64Functions(t *testing.T) {
	var testString = "2O/VY9uDc4Gb7ijn4Kxmmk8cOiLvpyBo93JpKL8HbBq9buWjULDOC2h8cG"
	encoded := Base64encode([]byte(testString))
	decoded, err := Base64decode(encoded)
	if err != nil {
		t.Error("Base64 decoding failed: " + err.Error())
	}

	if string(decoded[:]) != testString {
		t.Error("Teststring " + testString + " decoded back to something different: " + string(decoded[:]))
	}
}

func TestNonceCreation(t *testing.T) {
	if len(CreateNonce(8)) != 8 {
		t.Error("Expected a nonce of 8 characters.")
	}
}
