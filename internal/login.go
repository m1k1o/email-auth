package internal

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/m1k1o/email-auth/internal/auth"
	"github.com/m1k1o/email-auth/internal/config"
	"github.com/m1k1o/email-auth/internal/mail"
	"github.com/m1k1o/email-auth/internal/page"
)

type login struct {
	app    config.App
	cookie config.Cookie

	auth auth.Store
	mail *mail.Manager
	page *page.Manager
}

func (l *login) newLogger(r *http.Request) zerolog.Logger {
	var ip string

	if l.app.Proxy {
		if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
			ip = xrip
		} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			i := strings.Index(xff, ",")
			if i == -1 {
				i = len(xff)
			}
			ip = xff[:i]
		}
	}

	if ip == "" || net.ParseIP(ip) == nil {
		// TODO: Remove port part.
		ip = r.RemoteAddr
	}

	return log.With().
		Str("remote-addr", ip).
		Str("user-agent", r.UserAgent()).
		Logger()
}

func (l *login) verifyRedirectLink(redirectTo string) bool {
	if redirectTo == "" {
		return false
	}

	redirectLink, err := url.Parse(redirectTo)
	if err != nil {
		return false
	}

	hostname := redirectLink.Hostname()
	return l.cookie.Domain == "" || strings.HasSuffix(hostname, l.cookie.Domain)
}

func (l *login) verifyEmail(email string) bool {
	email = strings.ToLower(email)

	// unspecified - allowed all
	if len(l.app.Emails) == 0 {
		return true
	}

	components := strings.Split(email, "@")
	_, domain := components[0], components[1]

	for _, rule := range l.app.Emails {
		rule = strings.ToLower(rule)

		// exact match
		if rule == email {
			return true
		}

		// domain match
		if strings.HasPrefix(rule, "@") && rule == "@"+domain {
			return true
		}
	}

	return false
}

func (l *login) setCookie(w http.ResponseWriter, token string) {
	var expires time.Time
	if token == "" {
		expires = time.Unix(0, 0)
	} else {
		expires = time.Now().Add(l.app.Expiration.Session)
	}

	sameSite := http.SameSiteDefaultMode
	if l.cookie.Secure {
		sameSite = http.SameSiteNoneMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     l.cookie.Name,
		Domain:   l.cookie.Domain,
		Value:    token,
		Expires:  expires,
		Secure:   l.cookie.Secure,
		SameSite: sameSite,
		HttpOnly: l.cookie.HttpOnly,
	})
}

func (l *login) linkAction(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := l.newLogger(r)

		token := r.URL.Query().Get("token")
		if token == "" || r.Method != "GET" {
			next.ServeHTTP(w, r)
			return
		}

		session, err := l.auth.Get(token)
		if errors.Is(err, auth.ErrTokenNotFound) || err == nil && session.LoggedIn() {
			logger.Warn().Msg("invalid login link")
			l.page.Error(w, "Invalid login link.", http.StatusBadRequest)
			return
		}

		if err != nil {
			logger.Err(err).Msg("unable to get session")
			l.page.Error(w, "Error while getting session, please contact your system administrator.", http.StatusInternalServerError)
			return
		}

		if session.Expired() {
			logger.Warn().Str("email", session.Email()).Msg("login link expired")
			l.page.Error(w, "Login link aleady expired, please request new.", http.StatusBadRequest)
			return
		}

		newToken, err := l.auth.Login(token)
		if err != nil {
			logger.Err(err).Str("email", session.Email()).Msg("unable to login")
			l.page.Error(w, "Error while logging in, please contact your system administrator.", http.StatusInternalServerError)
			return
		}

		l.setCookie(w, newToken)

		to := r.URL.Query().Get("to")
		if !l.verifyRedirectLink(to) {
			to = l.app.Url
		}

		logger.Info().Str("email", session.Email()).Str("to", to).Msg("login verified")
		http.Redirect(w, r, to, http.StatusTemporaryRedirect)
	}
}

func (l *login) mainPage(w http.ResponseWriter, r *http.Request) {
	logger := l.newLogger(r)

	if r.Method == "GET" {
		logger.Debug().Msg("requested login page")
		l.page.Login(w, r)
		return
	}

	if r.Method == "POST" {
		email := r.FormValue("email")
		if email == "" {
			logger.Debug().Str("email", email).Msg("no email provided")
			l.page.Error(w, "No email provided.", http.StatusBadRequest)
			return
		}

		if !l.verifyEmail(email) {
			logger.Warn().Str("email", email).Msg("email not allowed")
			l.page.Error(w, "Given email is not permitted for login, please contact your system administrator.", http.StatusForbidden)
			return
		}

		token, err := l.auth.Add(email)
		if err != nil {
			logger.Err(err).Str("email", email).Msg("unable to create session")
			l.page.Error(w, "Error while creating session, please contact your system administrator.", http.StatusInternalServerError)
			return
		}

		redirectTo := r.URL.Query().Get("to")
		err = l.mail.Send(email, token, redirectTo)
		if err != nil {
			logger.Err(err).Str("email", email).Msg("unable to send email")
			l.page.Error(w, "Error while sending email, please contact your system administrator.", http.StatusInternalServerError)
			return
		}

		logger.Info().Str("email", email).Msg("email sent")
		l.page.Success(w, "Please check your email inbox for further instructions.")
		return
	}

	logger.Debug().Str("method", r.Method).Msg("method not allowed")
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}

func (l *login) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger := l.newLogger(r)

	username, err := AuthFromContext(r.Context())
	if err == nil {
		token := tokenFromContext(r.Context())
		if token != "" && r.Method == "POST" && r.FormValue("logout") != "" {
			// remove cookie
			l.setCookie(w, "")

			err := l.auth.Delete(token)
			if err != nil {
				logger.Err(err).Msg("unable to delete session")
				l.page.Error(w, "Error while deleting session, please contact your system administrator.", http.StatusInternalServerError)
				return
			}

			logger.Info().Str("email", username).Msg("session deleted")
			l.page.Success(w, "You have been successfully logged out.")
			return
		}

		l.page.LoggedIn(w)
		return
	}

	if errors.Is(err, ErrNoAuthentication) {
		handler := http.HandlerFunc(l.mainPage)
		handler = l.linkAction(handler)
		handler.ServeHTTP(w, r)
		return
	}

	if errors.Is(err, ErrApiUserNotFound) || errors.Is(err, ErrApiWrongPassword) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrSessionNotLoggedIn) {
		// remove cookie
		l.setCookie(w, "")

		logger.Warn().Msg("session not found")
		l.page.Error(w, "Session not found, please log in again.", http.StatusUnauthorized)
		return
	}

	if errors.Is(err, ErrSessionExpired) {
		// remove cookie
		l.setCookie(w, "")

		logger.Warn().Str("email", username).Msg("session expired")
		l.page.Error(w, "Session expried, please log in again.", http.StatusForbidden)
		return
	}

	logger.Err(err).Msg("unable to get session")
	l.page.Error(w, "Error while getting session, please contact your system administrator.", http.StatusInternalServerError)
}
