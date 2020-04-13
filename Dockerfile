FROM golang:1.14-alpine3.11 as builder
RUN apk update && apk add git
ADD . /go/src/ambassador-auth-oidc/
WORKDIR /go/src/ambassador-auth-oidc
RUN go mod vendor
RUN go build -o /go/bin/ambassador-auth-oidc

FROM alpine:3.11
LABEL org.label-schema.vcs-url="https://github.com/ajmyyra/ambassador-auth-oidc"
LABEL org.label-schema.version="2.0"
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
RUN addgroup -S auth && adduser -S -G auth auth
USER auth
WORKDIR /app
COPY --from=builder /go/bin/ambassador-auth-oidc /app/
ENTRYPOINT [ "./ambassador-auth-oidc" ]
