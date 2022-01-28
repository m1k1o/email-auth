package page

import (
	"html/template"
	"io/ioutil"
	"net/http"

	"github.com/m1k1o/email-auth/internal/config"

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

func (manager *Manager) serve(w http.ResponseWriter, template Template) {
	err := manager.tmpl.Execute(w, template)
	if err != nil {
		log.Err(err).Msg("error while serving page")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (manager *Manager) Error(w http.ResponseWriter, msg string, code int) {
	w.WriteHeader(code)

	manager.serve(w, Template{
		AppName: manager.app.Name,
		AppUrl:  manager.app.Url,
		Error:   msg,
	})
}

func (manager *Manager) Success(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusOK)

	manager.serve(w, Template{
		AppName: manager.app.Name,
		AppUrl:  manager.app.Url,
		Success: msg,
	})
}

func (manager *Manager) Login(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)

	manager.serve(w, Template{
		AppName: manager.app.Name,
		AppUrl:  manager.app.GetUrl(r),
	})
}

func (manager *Manager) LoggedIn(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)

	manager.serve(w, Template{
		AppName:  manager.app.Name,
		AppUrl:   manager.app.Url,
		LoggedIn: true,
	})
}
