package authentication

import (
	"github.com/ajmyyra/ambassador-auth-oidc/pkg/persistence"
	"github.com/ajmyyra/ambassador-auth-oidc/pkg/util"
	"net/url"
	"reflect"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

func newTestKeystore() persistence.Keystore {
	keystore, err := persistence.New("", "")
	if err != nil {
		panic(err)
	}

	return keystore
}

func newTestAuthNConfig() AuthNConfig {
	selfAddr, _ := url.Parse("http://test.example.com")
	oidcProvider, _ := url.Parse("http://oidc-test.example.com")

	return AuthNConfig{
		SelfAddress:  *selfAddr,
		OIDCProvider: *oidcProvider,
		OIDCScopes:   []string{"openid", "profile", "email"},
		ClientId:     "foo",
		ClientSecret: "bar",
		JWTSecret:    []byte("abc543210"),
		UserInfo:     true,
		LogoutCookie: false,
	}
}

func newTestAuthNController() AuthNController {
	testConfig := newTestAuthNConfig()
	testKeystore := newTestKeystore()

	// TODO mock OIDC endpoint with net/http/httptest to allow AuthNController creation and to test different scenarios.
	authNController, err := New(testConfig, &testKeystore)
	if err != nil {
		panic(err)
	}

	return authNController
}


func TestCookieCreation(t *testing.T) {
	var testdomain = "testing.com"
	var userinfo = []byte("testfoo1234567890")
	var expiration = time.Now().Add(time.Hour)
	testJwt := createSignedJWT(userinfo, expiration)
	testCookie := CreateCookie(testJwt, expiration, testdomain)

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

	uifClaim, err := util.Base64decode(cookieJWT.Claims.(jwt.MapClaims)["uif"].(string))
	if err != nil {
		t.Error("Trouble getting uif claim from JWT: " + err.Error())
	}

	if !reflect.DeepEqual(userinfo, uifClaim) {
		t.Error("Userinfo different from uif claim. Userinfo: " + string(userinfo[:]) + ", uif claim: " + string(uifClaim[:]))
	}
}
