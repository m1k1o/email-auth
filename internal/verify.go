package internal

import (
	"context"
	"errors"
	"net/http"

	"github.com/m1k1o/email-auth/internal/auth"
	"github.com/m1k1o/email-auth/internal/config"
)

type authData string

const (
	authErr   authData = "email-auth-err"
	authUser  authData = "email-auth-user"
	authToken authData = "email-auth-token"
)

func AuthFromContext(ctx context.Context) (string, error) {
	err, ok := ctx.Value(authErr).(error)
	if ok {
		return "", err
	}

	user, ok := ctx.Value(authUser).(string)
	if ok {
		return user, nil
	}

	return "", errors.New("no authentication middleware data found")
}

func tokenFromContext(ctx context.Context) string {
	token, ok := ctx.Value(authToken).(string)
	if !ok || token == "" {
		return ""
	}

	return token
}

type verify struct {
	app    config.App
	cookie config.Cookie

	auth auth.Store
}

var (
	ErrNoAuthentication = errors.New("no authentication provided")
	// http basic auth
	ErrApiUserNotFound  = errors.New("api user not found")
	ErrApiWrongPassword = errors.New("api wrong password")
	// session cookie auth
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionNotLoggedIn = errors.New("session not logged in")
	ErrSessionExpired     = errors.New("session expired")
)

func (v *verify) basicAuth(r *http.Request) (string, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return "", ErrNoAuthentication
	}

	pass, found := v.app.Auths[username]
	if !found {
		return "", ErrApiUserNotFound
	}

	if pass != password {
		return "", ErrApiWrongPassword
	}

	return username, nil
}

func (v *verify) sessionCookie(r *http.Request) (token string, session *auth.Session, err error) {
	cookie, err := r.Cookie(v.cookie.Name)
	if err != nil {
		return "", nil, ErrNoAuthentication
	}

	token = cookie.Value
	session, err = v.auth.Get(token)

	if err == nil {
		if !session.LoggedIn() {
			err = ErrSessionNotLoggedIn
		} else if session.Expired() {
			err = ErrSessionExpired
		}
	} else if errors.Is(err, auth.ErrTokenNotFound) {
		err = ErrSessionNotFound
	}

	return
}

func (v *verify) WithAuthentication(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		username, err := v.basicAuth(r)
		if err != ErrNoAuthentication {
			if err != nil {
				ctx = context.WithValue(ctx, authErr, err)
			} else {
				ctx = context.WithValue(ctx, authUser, username)
			}
		} else {
			token, session, err := v.sessionCookie(r)
			if err != nil {
				ctx = context.WithValue(ctx, authErr, err)
			} else {
				ctx = context.WithValue(ctx, authToken, token)
				ctx = context.WithValue(ctx, authUser, session.Email())
			}
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (v *verify) WithRedirect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// is authenticated
		if _, err := AuthFromContext(r.Context()); err == nil {
			next.ServeHTTP(w, r)
			return
		}

		if !v.app.Proxy {
			http.Redirect(w, r, v.app.Url, http.StatusTemporaryRedirect)
			return
		}

		targetUrl := r.Header.Get("X-Original-URL")
		if targetUrl != "" {
			redirectTo, err := v.app.CreateUrl("", targetUrl)
			if err != nil {
				redirectTo = v.app.Url
			}

			http.Redirect(w, r, redirectTo, http.StatusTemporaryRedirect)
			return
		}

		proto := r.Header.Get("X-Forwarded-Proto")
		host := r.Header.Get("X-Forwarded-Host")
		port := r.Header.Get("X-Forwarded-Port")
		if proto == "" || host == "" || port == "" {
			http.Redirect(w, r, v.app.Url, http.StatusTemporaryRedirect)
			return
		}

		targetUrl = proto + "://" + host
		if (port != "80" || proto != "http") && (port != "443" || proto != "https") {
			targetUrl += ":" + port
		}
		targetUrl += r.Header.Get("X-Forwarded-Uri")

		redirectTo, err := v.app.CreateUrl("", targetUrl)
		if err != nil {
			redirectTo = v.app.Url
		}

		http.Redirect(w, r, redirectTo, http.StatusTemporaryRedirect)
	}
}

func (v *verify) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := AuthFromContext(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if v.app.Header.Enabled {
			w.Header().Set(v.app.Header.Name, user)
		}

		w.Write([]byte("OK"))
	})

	handler = v.WithRedirect(handler)
	handler = v.WithAuthentication(handler)
	handler.ServeHTTP(w, r)
}
