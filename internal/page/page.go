package page

import (
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"

	"email-proxy-auth/internal/config"

	"github.com/rs/zerolog/log"
)

type Template struct {
	AppName  string
	AppUrl   string
	Success  string
	Error    string
	LoggedIn bool
}

type Manager struct {
	app  config.App
	tmpl *template.Template
}

func New(templatePath string, app config.App) (*Manager, error) {
	html, err := ioutil.ReadFile(templatePath)
	if err != nil {
		return nil, err
	}

	tmpl, err := template.New("login-page").Parse(string(html))
	if err != nil {
		return nil, err
	}

	return &Manager{
		app:  app,
		tmpl: tmpl,
	}, nil
}

func (manager *Manager) getAppUrl(redirectTo string) (string, error) {
	loginLink, err := url.Parse(manager.app.Url)
	if err != nil {
		return "", err
	}

	q := loginLink.Query()
	if redirectTo != "" {
		q.Add("to", redirectTo)
	}
	loginLink.RawQuery = q.Encode()

	return loginLink.String(), nil
}
func (manager *Manager) Error(w http.ResponseWriter, msg string, code int) {
	w.WriteHeader(code)

	if err := manager.tmpl.Execute(w, Template{
		AppName: manager.app.Name,
		AppUrl:  manager.app.Url,
		Error:   msg,
	}); err != nil {
		log.Err(err).Msg("error while serving page")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (manager *Manager) Success(w http.ResponseWriter, msg string) {
	if err := manager.tmpl.Execute(w, Template{
		AppName: manager.app.Name,
		AppUrl:  manager.app.Url,
		Success: msg,
	}); err != nil {
		log.Err(err).Msg("error while serving page")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (manager *Manager) Login(w http.ResponseWriter, redirectTo string) {
	w.WriteHeader(http.StatusUnauthorized)

	appUrl, err := manager.getAppUrl(redirectTo)
	if err != nil {
		log.Err(err).Msg("error while serving page")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	if err := manager.tmpl.Execute(w, Template{
		AppName: manager.app.Name,
		AppUrl:  appUrl,
	}); err != nil {
		log.Err(err).Msg("error while serving page")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (manager *Manager) LoggedIn(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)

	if err := manager.tmpl.Execute(w, Template{
		AppName:  manager.app.Name,
		AppUrl:   manager.app.Url,
		LoggedIn: true,
	}); err != nil {
		log.Err(err).Msg("error while serving page")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}
