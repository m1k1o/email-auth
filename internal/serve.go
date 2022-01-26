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

	"email-proxy-auth/internal/auth"
	"email-proxy-auth/internal/config"
	"email-proxy-auth/internal/mail"
	"email-proxy-auth/internal/page"
)

type serve struct {
	config config.Serve

	auth auth.Store
	mail *mail.Manager
	page *page.Manager
}

func (s *serve) newLogger(r *http.Request) zerolog.Logger {
	var ip string

	if s.config.App.Proxy {
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

func (s *serve) verifyRedirectLink(redirectTo string) bool {
	if redirectTo == "" {
		return false
	}

	redirectLink, err := url.Parse(redirectTo)
	if err != nil {
		return false
	}

	hostname := redirectLink.Hostname()
	return s.config.Cookie.Domain == "" || strings.HasSuffix(hostname, s.config.Cookie.Domain)
}

func (s *serve) verifyEmail(email string) bool {
	email = strings.ToLower(email)

	// unspecified - allowed all
	if len(s.config.App.Emails) == 0 {
		return true
	}

	components := strings.Split(email, "@")
	_, domain := components[0], components[1]

	for _, rule := range s.config.App.Emails {
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

func (s *serve) setCookie(w http.ResponseWriter, token string) {
	var expires time.Time
	if token == "" {
		expires = time.Unix(0, 0)
	} else {
		expires = time.Now().Add(s.config.App.Expiration.Session)
	}

	sameSite := http.SameSiteDefaultMode
	if s.config.Cookie.Secure {
		sameSite = http.SameSiteNoneMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     s.config.Cookie.Name,
		Domain:   s.config.Cookie.Domain,
		Value:    token,
		Expires:  expires,
		Secure:   s.config.Cookie.Secure,
		SameSite: sameSite,
		HttpOnly: s.config.Cookie.HttpOnly,
	})
}
func (s *serve) loginAction(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := s.newLogger(r)

		token := r.URL.Query().Get("token")
		if token == "" || r.Method != "GET" {
			next.ServeHTTP(w, r)
			return
		}

		session, err := s.auth.Get(token)
		if errors.Is(err, auth.ErrTokenNotFound) || err == nil && session.LoggedIn() {
			logger.Warn().Msg("invalid login link")
			s.page.Error(w, "Invalid login link.", http.StatusBadRequest)
			return
		}

		if err != nil {
			logger.Err(err).Msg("unable to get session")
			s.page.Error(w, "Error while getting session, please contact your system administrator.", http.StatusInternalServerError)
			return
		}

		if session.Expired() {
			logger.Warn().Str("email", session.Email()).Msg("login link expired")
			s.page.Error(w, "Login link aleady expired, please request new.", http.StatusBadRequest)
			return
		}

		newToken, err := s.auth.Login(token)
		if err != nil {
			logger.Err(err).Str("email", session.Email()).Msg("unable to login")
			s.page.Error(w, "Error while logging in, please contact your system administrator.", http.StatusInternalServerError)
			return
		}

		s.setCookie(w, newToken)

		to := r.URL.Query().Get("to")
		if !s.verifyRedirectLink(to) {
			to = s.config.App.Url
		}

		logger.Info().Str("email", session.Email()).Str("to", to).Msg("login verified")
		http.Redirect(w, r, to, http.StatusTemporaryRedirect)
	}
}

func (s *serve) loginPage(w http.ResponseWriter, r *http.Request) {
	logger := s.newLogger(r)

	if r.Method == "GET" {
		logger.Debug().Msg("requested login page")
		s.page.Login(w, r)
		return
	}

	if r.Method == "POST" {
		email := r.FormValue("email")
		if email == "" {
			logger.Debug().Str("email", email).Msg("no email provided")
			s.page.Error(w, "No email provided.", http.StatusBadRequest)
			return
		}

		if !s.verifyEmail(email) {
			logger.Warn().Str("email", email).Msg("email not allowed")
			s.page.Error(w, "Given email is not permitted for login, please contact your system administrator.", http.StatusForbidden)
			return
		}

		token, err := s.auth.Add(email)
		if err != nil {
			logger.Err(err).Str("email", email).Msg("unable to create session")
			s.page.Error(w, "Error while creating session, please contact your system administrator.", http.StatusInternalServerError)
			return
		}

		redirectTo := r.URL.Query().Get("to")
		err = s.mail.Send(email, token, redirectTo)
		if err != nil {
			logger.Err(err).Str("email", email).Msg("unable to send email")
			s.page.Error(w, "Error while sending email, please contact your system administrator.", http.StatusInternalServerError)
			return
		}

		logger.Info().Str("email", email).Msg("email sent")
		s.page.Success(w, "Please check your email inbox for further instructions.")
		return
	}

	logger.Debug().Str("method", r.Method).Msg("method not allowed")
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}

func (s *serve) mainPage(w http.ResponseWriter, r *http.Request) {
	logger := s.newLogger(r)

	sessionCookie, err := r.Cookie(s.config.Cookie.Name)
	if err != nil {
		s.loginPage(w, r)
		return
	}

	token := sessionCookie.Value
	session, err := s.auth.Get(token)
	if errors.Is(err, auth.ErrTokenNotFound) || err == nil && !session.LoggedIn() {
		// remove cookie
		s.setCookie(w, "")

		logger.Warn().Msg("session token not found")
		s.page.Error(w, "Session token not found, please log in again.", http.StatusUnauthorized)
		return
	}

	if err != nil {
		logger.Err(err).Msg("unable to get session")
		s.page.Error(w, "Error while getting session, please contact your system administrator.", http.StatusInternalServerError)
		return
	}

	if session.Expired() {
		// remove cookie
		s.setCookie(w, "")

		logger.Warn().Str("email", session.Email()).Msg("session expired")
		s.page.Error(w, "Session expried, please log in again.", http.StatusForbidden)
		return
	}

	if r.Method == "POST" && r.FormValue("logout") != "" {
		// remove cookie
		s.setCookie(w, "")

		err := s.auth.Delete(token)
		if err != nil {
			logger.Err(err).Msg("unable to delete session")
			s.page.Error(w, "Error while deleting session, please contact your system administrator.", http.StatusInternalServerError)
			return
		}

		logger.Info().Str("email", session.Email()).Msg("session deleted")
		s.page.Success(w, "You have been successfully logged out.")
		return
	}

	s.page.LoggedIn(w)
}

func (s *serve) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler := s.loginAction(s.mainPage)
	handler.ServeHTTP(w, r)
}

func (s *serve) Verify(w http.ResponseWriter, r *http.Request) {
	appUrl := s.config.App.GetUrl(r)

	sessionCookie, err := r.Cookie(s.config.Cookie.Name)
	if err != nil {
		http.Redirect(w, r, appUrl, http.StatusTemporaryRedirect)
		return
	}

	token := sessionCookie.Value
	session, err := s.auth.Get(token)
	if err != nil || !session.LoggedIn() || session.Expired() {
		http.Redirect(w, r, appUrl, http.StatusTemporaryRedirect)
		return
	}

	w.WriteHeader(http.StatusOK)
	if s.config.App.Header.Enabled {
		w.Header().Set(s.config.App.Header.Name, session.Email())
	}
	w.Write([]byte("OK"))
}

func Serve(config config.Serve) (err error) {
	manager := &serve{
		config: config,
		auth:   auth.NewStore(config.Redis, config.App.Expiration),
	}

	manager.mail, err = mail.New(config.Tmpl.Email, config.App, config.Email)
	if err != nil {
		return
	}

	manager.page, err = page.New(config.Tmpl.Page, config.App)
	if err != nil {
		return
	}

	http.Handle("/", manager)
	http.HandleFunc("/verify", manager.Verify)

	log.Info().Msgf("starting http server on %s", config.App.Bind)
	return http.ListenAndServe(config.App.Bind, nil)
}
