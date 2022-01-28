package internal

import (
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/m1k1o/email-auth/internal/auth"
	"github.com/m1k1o/email-auth/internal/config"
	"github.com/m1k1o/email-auth/internal/mail"
	"github.com/m1k1o/email-auth/internal/page"
)

func Serve(config config.Serve) (err error) {
	authStore := auth.NewStore(config.Redis, config.App.Expiration)

	login := &login{
		app:    config.App,
		cookie: config.Cookie,
		auth:   authStore,
	}

	login.mail, err = mail.New(config.Tmpl.Email, config.App, config.Email)
	if err != nil {
		log.Err(err).Msg("failed to get mail manager")
		return
	}

	login.page, err = page.New(config.Tmpl.Page, config.App)
	if err != nil {
		log.Err(err).Msg("failed to get page manager")
		return
	}

	verify := &verify{
		app:    config.App,
		cookie: config.Cookie,
		auth:   authStore,
	}

	http.Handle("/", verify.WithAuthentication(login.ServeHTTP))
	http.Handle("/verify", verify)

	log.Info().Msgf("starting http server on %s", config.App.Bind)
	return http.ListenAndServe(config.App.Bind, nil)
}
