FROM golang:1.10-alpine3.8 as builder
RUN apk update && apk add git
ADD *.go /go/src/ambassador-auth-oidc/
WORKDIR /go/src/ambassador-auth-oidc
ADD Gopkg.toml .
ADD Gopkg.lock .
RUN go get github.com/golang/dep/cmd/dep
RUN dep ensure
RUN go build -o /go/bin/ambassador-auth-oidc

FROM alpine:3.8
LABEL org.label-schema.vcs-url="https://github.com/ajmyyra/ambassador-auth-oidc"
LABEL org.label-schema.version="1.3"
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
RUN addgroup -S auth && adduser -S -G auth auth
USER auth
WORKDIR /app
COPY --from=builder /go/bin/ambassador-auth-oidc /app/
ENTRYPOINT [ "./ambassador-auth-oidc" ]
