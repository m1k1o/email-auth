# email auth

A simple passwordless authentication middleware that uses only email as the authentication provider.

## Motivation

I wanted to restrict access to a simple HTTP service for certain users without the hassle of managing their passwords. Did not have [LDAP server](https://ldap.com/), [SSO](https://en.wikipedia.org/wiki/Single_sign-on) or [OAuth 2.0 service](https://oauth.net/2/) where their identity would be already managed. Using [Basic authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) was not an option, because I would need to create a password for every single user and give it to them.

I created this simple service that prompts for a user's email, checks it against a whitelist, and then sends a login link to the provided email. Once this login link is visited, the user is granted access for a certain amount of time. Previously mentioned authentications should be used whenever available. This project is just for the sake of simplicity and minimal overhead for its users and also developer, for the applications where email communication can be trusted to grant tokens.

## Features

- Passwordless authentication.
- Manage access per email or per domain.
- Plug & Play - you only need to provide access to SMTP server.
- Easy HTML template customization.
- Optional Redis support.
- Optional API access using HTTP Basic Auth.

## Getting started

You can find docker images on [Github Package Registry](https://github.com/m1k1o/email-auth/pkgs/container/email-auth).

```yaml
services:
  email-auth:
    image: ghcr.io/m1k1o/email-auth:1.0
    environment:
      CFG_APP_URL: "https://127.0.0.1/auth"
      CFG_EMAIL_HOST: "smtp4dev"
      CFG_REDIS_ENABLED: "true"
      CFG_REDIS_HOST: "redis"
    ports:
     - "8080:8080"
```

You can copy `config.yaml` and modify, then mount it to `./config.yaml:/app/config.yaml`.

Or you can set data using environment variables. They must start with `CFG_`, all upercase and muliple levels joined by `_`. E.g. `CFG_APP_URL` is key `url` located in section `app` inside the config file.

If you visit `/verify` URL, you get `HTTP 200` (+ header with username, if specified in config) for logged in users, otherwise `HTTP 307` redirect to app URL. For all other URLs that you visit, you get the login page. That means, any path prefix is accepted and you can have your login page at the `/auth` endpoint.

### Example with traefik

- Download `docker-compose.yaml`. Run `docker-compose up -d`.
- Navigate to `https://127.0.0.1/protected`, you will be prompted to enter your email. Only `@test.com` domain is permitted.
- After requesting login link, open `http://127.0.0.1:5000` in new tab to receive test emails.
- Visit the link you received in your email.
- You will be redirected to the originally accessed service.

## Screenshots

You can easily customize both page and email template in `./tmpl` folder.

### Login page
![Login page](docs/login.png)

### Login link received via email
![Email](docs/email.png)

### Login confirmation
Or HTTP redirect to accessed service based on HTTP Referer.

![Logged in](docs/logged-in.png)
