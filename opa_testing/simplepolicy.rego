package httpapi.authz

admins = ["admin@example.com"]

default allow = false

allow {
	input.method == "GET"
	input.path == ["headers"]
        admins[_] == input.user
}
