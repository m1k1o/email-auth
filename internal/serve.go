package internal

import (
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

	auth *auth.Manager
	mail *mail.Manager
	page *page.Manager
}

func (s *serve) newLogger(r *http.Request) zerolog.Logger {
	return log.With().
		Str("remote-addr", r.RemoteAddr).
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
	// unspecified - allowed all
	if len(s.config.App.Emails) == 0 {
		return true
	}

	components := strings.Split(email, "@")
	_, domain := components[0], components[1]

	for _, rule := range s.config.App.Emails {
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

func (s *serve) loginAction(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := s.newLogger(r)

		secret := r.URL.Query().Get("login")
		if secret == "" || r.Method != "GET" {
			next.ServeHTTP(w, r)
			return
		}

		session, ok := s.auth.Get(secret)
		if !ok || session.LoggedIn() {
			next.ServeHTTP(w, r)
			return
		}

		profile := session.Profile()
		if session.Expired() {
			logger.Warn().Str("email", profile.Email).Msg("link expired")
			s.page.Error(w, "Link already expired, please request new", http.StatusBadRequest)
			return
		}

		s.auth.Login(session)

		sameSite := http.SameSiteDefaultMode
		if s.config.Cookie.Secure {
			sameSite = http.SameSiteNoneMode
		}

		http.SetCookie(w, &http.Cookie{
			Name:     s.config.Cookie.Name,
			Domain:   s.config.Cookie.Domain,
			Value:    session.Token(),
			Expires:  time.Now().Add(s.config.Cookie.Expiration),
			Secure:   s.config.Cookie.Secure,
			SameSite: sameSite,
			HttpOnly: s.config.Cookie.HttpOnly,
		})

		to := r.URL.Query().Get("to")
		if !s.verifyRedirectLink(to) {
			to = s.config.App.Url
		}

		logger.Info().Str("email", profile.Email).Str("to", to).Msg("login verified")
		http.Redirect(w, r, to, http.StatusTemporaryRedirect)
	}
}

func (s *serve) loginPage(w http.ResponseWriter, r *http.Request) {
	logger := s.newLogger(r)
	redirectTo := r.URL.Query().Get("to")

	if r.Method == "GET" {
		log.Debug().Msg("requested login page")
		s.page.Login(w, redirectTo)
		return
	}

	if r.Method == "POST" {
		email := r.FormValue("email")
		if email == "" {
			logger.Debug().Str("email", email).Msg("no email provided")
			s.page.Error(w, "No email provided", http.StatusBadRequest)
			return
		}

		if !s.verifyEmail(email) {
			logger.Warn().Str("email", email).Msg("email not allowed")
			s.page.Error(w, "Given E-Mail is not permitted for login, please contact your system administrator", http.StatusForbidden)
			return
		}

		session := s.auth.Create(auth.Profile{
			Email: email,
		})

		err := s.mail.Send(session, redirectTo)
		if err != nil {
			logger.Err(err).Str("email", email).Msg("unable to send email")
			s.page.Error(w, "Unable to send email, please contact your system administrator", http.StatusInternalServerError)
			return
		}

		logger.Info().Str("email", email).Msg("email sent")
		s.page.Success(w, "Please check your E-Mail inbox for further instructions.")
		return
	}

	logger.Debug().Msg("method not allowed")
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
	session, ok := s.auth.Get(token)
	if !ok || !session.LoggedIn() {
		// remove cookie
		sessionCookie.Expires = time.Unix(0, 0)
		http.SetCookie(w, sessionCookie)

		logger.Warn().Str("token", token).Msg("token not found")
		s.page.Error(w, "Token not found", http.StatusUnauthorized)
		return
	}

	profile := session.Profile()
	if session.Expired() {
		// remove cookie
		sessionCookie.Expires = time.Unix(0, 0)
		http.SetCookie(w, sessionCookie)

		logger.Warn().Str("email", profile.Email).Msg("session expired")
		s.page.Error(w, "Session expried", http.StatusForbidden)
		return
	}

	if r.Method == "POST" && r.FormValue("logout") != "" {
		s.auth.Delete(session)

		// remove cookie
		sessionCookie.Expires = time.Unix(0, 0)
		http.SetCookie(w, sessionCookie)

		logger.Info().Str("email", profile.Email).Msg("logged out")
		s.page.Success(w, "You have been successfully logged out")
		return
	}

	w.Header().Set("X-Auth-Email", profile.Email)
	s.page.LoggedIn(w)
}

func (s *serve) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler := s.loginAction(s.mainPage)
	handler.ServeHTTP(w, r)
}

func Serve(config config.Serve) (err error) {
	manager := &serve{
		config: config,
	}

	manager.auth = auth.New(auth.Config{
		Expiration: config.Cookie.Expiration,
	})

	manager.mail, err = mail.New(mail.Config{
		TemplatePath: config.Tmpl.Email,

		App:   config.App,
		Email: config.Email,
	})

	if err != nil {
		return
	}

	manager.page, err = page.New(page.Config{
		TemplatePath: config.Tmpl.Page,

		App: config.App,
	})

	if err != nil {
		return
	}

	http.Handle("/", manager)

	log.Info().Msgf("Starting http server on %s", config.App.Bind)
	return http.ListenAndServe(config.App.Bind, nil)
}
