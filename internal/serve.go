package internal

import (
	"net/http"
	"time"

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

func (s *serve) loginAction(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secret := r.URL.Query().Get("login")
		if secret == "" || r.Method != "GET" {
			next.ServeHTTP(w, r)
			return
		}

		session, ok := s.auth.GetBySecret(secret)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		if session.Expired() {
			s.page.Error(w, "Link already expired, please request new", http.StatusBadRequest)
			return
		}

		if session.LoggedIn() {
			s.page.Error(w, "Link has been already used, please request new", http.StatusConflict)
			return
		}

		s.auth.Login(session)

		sameSite := http.SameSiteDefaultMode
		if s.config.Cookie.Secure {
			sameSite = http.SameSiteNoneMode
		}

		http.SetCookie(w, &http.Cookie{
			Name:     s.config.Cookie.Name,
			Value:    session.Token(),
			Expires:  time.Now().Add(s.config.Cookie.Expiration),
			Secure:   s.config.Cookie.Secure,
			SameSite: sameSite,
			HttpOnly: s.config.Cookie.HttpOnly,
		})

		// TODO: Check redirect against whitelist.
		redirectTo := r.URL.Query().Get("to")
		if redirectTo == "" {
			redirectTo = s.config.App.Url
		}

		http.Redirect(w, r, redirectTo, http.StatusTemporaryRedirect)
	}
}

func (s *serve) loginPage(w http.ResponseWriter, r *http.Request) {
	redirectTo := r.URL.Query().Get("to")

	if r.Method == "GET" {
		s.page.Login(w, redirectTo)
		return
	}

	if r.Method == "POST" {
		usrEmail := r.FormValue("email")
		if usrEmail == "" {
			s.page.Error(w, "No email provided", http.StatusBadRequest)
			return
		}

		// TODO: Check email against whitelist.

		session := s.auth.Create(auth.Profile{
			Email: usrEmail,
		})

		err := s.mail.Send(session, redirectTo)
		if err != nil {
			s.page.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		s.page.Success(w, "Please check your E-Mail inbox for further instructions.")
		return
	}

	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}

func (s *serve) mainPage(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie(s.config.Cookie.Name)
	if err != nil {
		s.loginPage(w, r)
		return
	}

	token := sessionCookie.Value
	session, ok := s.auth.GetByToken(token)
	if !ok {
		// remove cookie
		sessionCookie.Expires = time.Unix(0, 0)
		http.SetCookie(w, sessionCookie)

		s.page.Error(w, "Token not found", http.StatusUnauthorized)
		return
	}

	if session.Expired() {
		// remove cookie
		sessionCookie.Expires = time.Unix(0, 0)
		http.SetCookie(w, sessionCookie)

		s.page.Error(w, "Session expried", http.StatusForbidden)
		return
	}

	if r.Method == "POST" && r.FormValue("logout") != "" {
		s.auth.Delete(session)

		// remove cookie
		sessionCookie.Expires = time.Unix(0, 0)
		http.SetCookie(w, sessionCookie)

		s.page.Success(w, "You have been successfully logged out")
		return
	}

	profile := session.Profile()
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
