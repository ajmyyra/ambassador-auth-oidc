FROM golang:1.10-stretch as builder
ADD . /go/src/ambassador-auth-oidc
RUN go get ./...
RUN cd /go/src/ambassador-auth-oidc && go build

FROM alpine:3.8
# As Alpine doesn't have glibc that is used to compile Go's binaries, 
# we must symlink to musl that provides same functionality.
RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
RUN addgroup -S auth && adduser -S -G auth auth
USER auth
WORKDIR /app
COPY --from=builder /go/bin/ambassador-auth-oidc /app/
ENTRYPOINT [ "./ambassador-auth-oidc" ]
