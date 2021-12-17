FROM golang:1.17 as builder
RUN apt update -y && apt install git -y
ADD *.go /go/src/ambassador-auth-oidc/
WORKDIR /go/src/ambassador-auth-oidc
#ADD Gopkg.toml .
#ADD Gopkg.lock .
ADD go.mod .
ADD go.sum .
#RUN go get github.com/golang/dep/cmd/dep
#RUN dep ensure
RUN go version
RUN go env
RUN go mod download
#RUN GOOS=linux GOARCH=amd64 go build -o /go/bin/ambassador-auth-oidc
RUN go build -o /go/bin/ambassador-auth-oidc

FROM alpine:3.15.0
LABEL org.label-schema.vcs-url="https://github.com/doc-ai/ambassador-auth-oidc"
LABEL org.label-schema.version="0.1"
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
RUN addgroup -S auth && adduser -S -G auth auth
USER auth
WORKDIR /app
COPY --from=builder /go/bin/ambassador-auth-oidc /app/
ENTRYPOINT [ "./ambassador-auth-oidc" ]
