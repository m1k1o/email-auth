#
# STAGE 1: build executable binary
#
FROM golang:1.18-bullseye as builder
WORKDIR /app

ARG VERSION
ARG GIT_COMMIT
ARG GIT_BRANCH

COPY . .
RUN ./build

#
# STAGE 2: build a small image
#
FROM scratch
WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/bin /usr/bin/email-auth
COPY tmpl tmpl

ENTRYPOINT [ "/usr/bin/email-auth" ]

EXPOSE 8080

CMD [ "serve", "--app.bind", ":8080" ]
