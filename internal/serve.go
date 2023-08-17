package internal

import (
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/m1k1o/email-auth/internal/auth"
	"github.com/m1k1o/email-auth/internal/config"
	"github.com/m1k1o/email-auth/internal/gui"
	"github.com/m1k1o/email-auth/internal/mail"
	"github.com/m1k1o/email-auth/internal/page"
)

type serve struct {
	login  *login
	verify *verify
}

func New(config config.Serve) (*serve, error) {
	var err error

	authStore := auth.NewStore(config.Redis, config.App.Expiration)

	login := &login{
		app:    config.App,
		cookie: config.Cookie,
		auth:   authStore,
	}

	login.mail, err = mail.New(config.Tmpl.Email, config.App, config.Email)
	if err != nil {
		return nil, err
	}

	login.page, err = page.New(config.Tmpl.Page, config.App)
	if err != nil {
		return nil, err
	}

	verify := &verify{
		app:    config.App,
		cookie: config.Cookie,
		auth:   authStore,
	}

	return &serve{
		login:  login,
		verify: verify,
	}, nil
}

func (s *serve) Login() http.Handler {
	return s.verify.WithAuthentication(s.login.ServeHTTP)
}

func (s *serve) Verify() http.Handler {
	return s.verify
}

func (s *serve) WithAuthentication(next http.HandlerFunc) http.HandlerFunc {
	return s.verify.WithAuthentication(next)
}

func (s *serve) WithRedirect(next http.HandlerFunc) http.HandlerFunc {
	return s.verify.WithAuthentication(s.verify.WithRedirect(next))
}

func ServeApp(config config.Serve) error {
	serve, err := New(config)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()

	mux.Handle("/", serve.Login())
	mux.Handle("/verify", serve.Verify())

	log.Info().Msgf("starting http app server on %s", config.App.Bind)
	return http.ListenAndServe(config.App.Bind, mux)
}

func ServeGui(config config.Serve) error {
	guiManager, err := gui.New(config.App, config.Gui)
	if err != nil {
		return err
	}

	err = guiManager.Init()
	if err != nil {
		return err
	}

	log.Info().Msgf("starting http gui server on %s", config.Gui.Bind)
	return http.ListenAndServe(config.Gui.Bind, guiManager)
}
