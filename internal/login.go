package internal

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
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
	app    *config.App
	cookie *config.Cookie

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

	if len(l.app.RedirectAllowlist) > 0 {
		for _, allowed := range l.app.RedirectAllowlist {
			// match scheme
			if allowed.Scheme != "" {
				if allowed.Scheme != redirectLink.Scheme {
					continue
				}
			}

			// match host
			if allowed.Host != "" {
				if allowed.Host != redirectLink.Host {
					continue
				}
			}

			// match path
			if allowed.Path != "" {
				if !strings.HasPrefix(redirectLink.Path, allowed.Path) {
					continue
				}
			}

			return true
		}
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

func (l *login) askForBasicAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
	l.page.Error(w, r, "Unauthorized.", http.StatusUnauthorized)
}

func (l *login) linkAction(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := l.newLogger(r)

		token := r.URL.Query().Get("token")
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}

		session, err := l.auth.Get(token)
		if errors.Is(err, auth.ErrTokenNotFound) || err == nil && session.LoggedIn() {
			logger.Warn().Msg("invalid login link")
			l.page.Error(w, r, "Invalid login link.", http.StatusBadRequest)
			return
		}

		if err != nil {
			logger.Err(err).Msg("unable to get session")
			l.page.Error(w, r, "Error while getting session, please contact your system administrator.", http.StatusInternalServerError)
			return
		}

		if session.Expired() {
			logger.Warn().Str("email", session.Email()).Msg("login link expired")
			l.page.Error(w, r, "Login link aleady expired, please request new.", http.StatusBadRequest)
			return
		}

		// log me in page
		if l.app.LoginBtn && r.Method == "GET" {
			l.page.LoginBtn(w, r)
			return
		}

		// login action
		if (l.app.LoginBtn && r.Method == "POST") || (!l.app.LoginBtn && r.Method == "GET") {
			newToken, err := l.auth.Login(token)
			if err != nil {
				logger.Err(err).Str("email", session.Email()).Msg("unable to login")
				l.page.Error(w, r, "Error while logging in, please contact your system administrator.", http.StatusInternalServerError)
				return
			}

			l.setCookie(w, newToken)

			to := r.URL.Query().Get("to")
			if !l.verifyRedirectLink(to) {
				to = l.app.Url
			}

			logger.Info().Str("email", session.Email()).Str("to", to).Msg("login verified")
			http.Redirect(w, r, to, http.StatusTemporaryRedirect)
			return
		}

		// invalid method
		next.ServeHTTP(w, r)
	}
}

func (l *login) mainPage(w http.ResponseWriter, r *http.Request) {
	logger := l.newLogger(r)

	if r.Method == "GET" {
		if ok, err := strconv.ParseBool(r.URL.Query().Get("login")); ok && err == nil {
			l.askForBasicAuth(w, r)
			return
		}

		logger.Debug().Msg("requested login page")
		l.page.Login(w, r)
		return
	}

	if r.Method == "POST" {
		email := r.FormValue("email")
		if email == "" {
			logger.Debug().Str("email", email).Msg("no email provided")
			l.page.Error(w, r, "No email provided.", http.StatusBadRequest)
			return
		}

		if !l.verifyEmail(email) {
			logger.Warn().Str("email", email).Msg("email not allowed")
			l.page.Error(w, r, "Given email is not permitted for login, please contact your system administrator.", http.StatusForbidden)
			return
		}

		token, err := l.auth.Add(email)
		if err != nil {
			logger.Err(err).Str("email", email).Msg("unable to create session")
			l.page.Error(w, r, "Error while creating session, please contact your system administrator.", http.StatusInternalServerError)
			return
		}

		redirectTo := r.URL.Query().Get("to")
		err = l.mail.Send(email, token, redirectTo)
		if err != nil {
			logger.Err(err).Str("email", email).Msg("unable to send email")
			l.page.Error(w, r, "Error while sending email, please contact your system administrator.", http.StatusInternalServerError)
			return
		}

		logger.Info().Str("email", email).Msg("email sent")
		l.page.Success(w, r, "Please check your email inbox for further instructions.")
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
		if r.Method == "POST" && r.FormValue("logout") != "" {
			// remove basic auth by asking for it again
			if token == "" {
				logger.Info().Str("username", username).Msg("logged out")
				l.askForBasicAuth(w, r)
				return
			}

			// remove cookie
			l.setCookie(w, "")

			err := l.auth.Delete(token)
			if err != nil {
				logger.Err(err).Msg("unable to delete session")
				l.page.Error(w, r, "Error while deleting session, please contact your system administrator.", http.StatusInternalServerError)
				return
			}

			logger.Info().Str("email", username).Msg("session deleted")
			l.page.Success(w, r, "You have been successfully logged out.")
			return
		}

		// if has ?login=1 and no token, redirect
		if ok, err := strconv.ParseBool(r.URL.Query().Get("login")); ok && err == nil && token == "" {
			to := r.URL.Query().Get("to")
			if !l.verifyRedirectLink(to) {
				to = l.app.Url
			}

			logger.Info().Str("username", username).Str("to", to).Msg("basic auth logged in")
			http.Redirect(w, r, to, http.StatusTemporaryRedirect)
			return
		}

		l.page.LoggedIn(w, r)
		return
	}

	if errors.Is(err, ErrNoAuthentication) {
		handler := http.HandlerFunc(l.mainPage)
		handler = l.linkAction(handler)
		handler.ServeHTTP(w, r)
		return
	}

	// remove basic auth by asking for it again
	if errors.Is(err, ErrApiUserNotFound) || errors.Is(err, ErrApiWrongPassword) {
		logger.Err(err).Msg("basic auth error")
		l.askForBasicAuth(w, r)
		return
	}

	if errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrSessionNotLoggedIn) {
		// remove cookie
		l.setCookie(w, "")

		logger.Warn().Msg("session not found")
		l.page.Error(w, r, "Session not found or expired, please log in again.", http.StatusUnauthorized)
		return
	}

	if errors.Is(err, ErrSessionExpired) {
		// remove cookie
		l.setCookie(w, "")

		logger.Warn().Str("email", username).Msg("session expired")
		l.page.Error(w, r, "Session expried, please log in again.", http.StatusForbidden)
		return
	}

	logger.Err(err).Msg("unable to get session")
	l.page.Error(w, r, "Error while getting session, please contact your system administrator.", http.StatusInternalServerError)
}
