# OpenID Connect for Ambassador API Gateway

Ambassador-Auth-OIDC offers OpenID Connect support as [Ambassador API Gateway](https://www.getambassador.io/)'s [AuthService manifest](https://www.getambassador.io/reference/services/auth-service).

## OpenID Connect

[OpenID Connect (OIDC)](http://openid.net/connect/) is an authentication layer on top of the OAuth 2.0 protocol. As OAuth 2.0 is fully supported by OpenID Connect, existing OAuth 2.0 implementations work with it out of the box.

Currently it only supports OIDC's [Authorization Code Flow](http://openid.net/specs/openid-connect-basic-1_0.html#CodeFlow), similar to OAuth 2.0 Authorization Code Grant. No immediate plan exists to support implicit or hybrid flows, but pull requests are more than welcome!

## Example auth flow

TODO

## Current status

Some finalisation needed (Dockerfile, etc), but should be quite ready for use. Feel free to try!