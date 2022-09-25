#
# STAGE 1: build executable binary
#
FROM golang:1.18-bullseye as builder
WORKDIR /app

COPY . .
RUN go get -v -t -d .
RUN ./build

#
# STAGE 2: build a small image
#
FROM scratch
WORKDIR /app

COPY --from=builder /app/bin /usr/bin/email-auth
COPY tmpl tmpl

ENTRYPOINT [ "email-auth" ]

EXPOSE 8080

CMD [ "serve", "--app.bind", ":8080" ]
