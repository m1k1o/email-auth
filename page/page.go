package page

import (
	"html/template"
	"io/ioutil"
	"net/http"
)

type Template struct {
	AppName  string
	Success  string
	Error    string
	LoggedIn bool
}

type Manager struct {
	config Config
	tmpl   *template.Template
}

func New(config Config) (*Manager, error) {
	html, err := ioutil.ReadFile(config.TemplatePath)
	if err != nil {
		return nil, err
	}

	tmpl, err := template.New("login-page").Parse(string(html))
	if err != nil {
		return nil, err
	}

	return &Manager{
		config: config,
		tmpl:   tmpl,
	}, nil
}

func (manager *Manager) Error(w http.ResponseWriter, msg string, code int) {
	w.WriteHeader(code)

	if err := manager.tmpl.Execute(w, Template{
		AppName: manager.config.AppName,
		Error:   msg,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (manager *Manager) Success(w http.ResponseWriter, msg string) {
	if err := manager.tmpl.Execute(w, Template{
		AppName: manager.config.AppName,
		Success: msg,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (manager *Manager) Login(w http.ResponseWriter) {
	if err := manager.tmpl.Execute(w, Template{
		AppName: manager.config.AppName,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (manager *Manager) LoggedIn(w http.ResponseWriter) {
	if err := manager.tmpl.Execute(w, Template{
		AppName:  manager.config.AppName,
		LoggedIn: true,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
