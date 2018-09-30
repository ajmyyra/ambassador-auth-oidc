# OpenID Connect for Ambassador API Gateway

Ambassador-Auth-OIDC offers OpenID Connect support as [Ambassador API Gateway](https://www.getambassador.io/)'s [AuthService manifest](https://www.getambassador.io/reference/services/auth-service).

## OpenID Connect

[OpenID Connect (OIDC)](http://openid.net/connect/) is an authentication layer on top of the OAuth 2.0 protocol. As OAuth 2.0 is fully supported by OpenID Connect, existing OAuth 2.0 implementations work with it out of the box.

Currently it only supports OIDC's [Authorization Code Flow](http://openid.net/specs/openid-connect-basic-1_0.html#CodeFlow), similar to OAuth 2.0 Authorization Code Grant. No immediate plan exists to support implicit or hybrid flows, but pull requests are more than welcome!

## Example auth flow

![](OIDC-flow.png)

## Options

Following environment variables are used by the software.

**Compulsary**
+ **OIDC_PROVIDER** URL to your OIDC provider, for example: https://you.eu.auth0.com/
+ **SELF_URL** URL of your application, for example: https://app.yourapp.com
+ **OIDC_SCOPES** OIDC scopes wanted for userinfo, for example: "profile email"
+ **CLIENT_ID** Client id for your application (given by your OIDC provider)
+ **CLIENT_SECRET** Client secret for your application
+ **REDIS_ADDRESS** Address for your Redis instance, IP or hostname
+ **REDIS_PASSWORD** Password for your Redis instance

**Optional**
+ **LOGOUT_COOKIE** Set to 'true' if you want to wipe the old cookie when logging out. This causes the browser to re-login next time your application is visited. Default is not enabled.

## Usage

All (except the Kubernetes one) expect that you've cloned the code into your own Go environment (for example, to $GOPATH/src/github.com/ajmyyra/ambassador-auth-oidc)

### As binary

Fetch dependencies, build the binary and run it.

```
cd /path/to/code
go get ./...
go build
./ambassador-auth-oidc
```

### In Docker

Build the container and start it with `docker run`. Replace options and Docker image id with your own. 

```
cd /path/to/code
docker build .
docker run -p 8080:8080 -e OIDC_PROVIDER="https://your-oidc-provider/" -e SELF_URL="http://your-server.com:8080" -e OIDC_SCOPES="profile email" -e CLIENT_ID="YOUR_CLIENT_ID" -e CLIENT_SECRET="YOUR_CLIENT_SECRET" -e REDIS_ADDRESS="redis:6379" -e REDIS_PASSWORD="YOUR_REDIS_PASSWORD" <Docker image id>
```

### With Ambassador in Kubernetes

 TODO, add to Docker hub first.