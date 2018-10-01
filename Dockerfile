FROM golang:1.10-alpine3.8 as builder
RUN apk update && apk add git
ADD . /go/src/ambassador-auth-oidc
RUN go get ./...
RUN cd /go/src/ambassador-auth-oidc && go build

FROM alpine:3.8
LABEL org.label-schema.vcs-url="https://github.com/ajmyyra/ambassador-auth-oidc"
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
RUN addgroup -S auth && adduser -S -G auth auth
USER auth
WORKDIR /app
COPY --from=builder /go/bin/ambassador-auth-oidc /app/
ENTRYPOINT [ "./ambassador-auth-oidc" ]
