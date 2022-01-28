#
# STAGE 1: build executable binary
#
FROM golang:1.17-buster as builder
WORKDIR /app

COPY . .
RUN go get -v -t -d .; \
    CGO_ENABLED=0 go build -o email-auth main.go

#
# STAGE 2: build a small image
#
FROM scratch
WORKDIR /app

COPY --from=builder /app/email-auth /usr/bin/email-auth
COPY tmpl tmpl

ENTRYPOINT [ "email-auth" ]

EXPOSE 8080

CMD [ "serve", "--app.bind", ":8080" ]
