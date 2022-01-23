package page

import (
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
)

type Template struct {
	AppName  string
	AppUrl   string
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

func (manager *Manager) getAppUrl(redirectTo string) (string, error) {
	loginLink, err := url.Parse(manager.config.AppUrl)
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
		AppName: manager.config.AppName,
		AppUrl:  manager.config.AppUrl,
		Error:   msg,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (manager *Manager) Success(w http.ResponseWriter, msg string) {
	if err := manager.tmpl.Execute(w, Template{
		AppName: manager.config.AppName,
		AppUrl:  manager.config.AppUrl,
		Success: msg,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (manager *Manager) Login(w http.ResponseWriter, redirectTo string) {
	appUrl, err := manager.getAppUrl(redirectTo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if err := manager.tmpl.Execute(w, Template{
		AppName: manager.config.AppName,
		AppUrl:  appUrl,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (manager *Manager) LoggedIn(w http.ResponseWriter) {
	if err := manager.tmpl.Execute(w, Template{
		AppName:  manager.config.AppName,
		AppUrl:   manager.config.AppUrl,
		LoggedIn: true,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
