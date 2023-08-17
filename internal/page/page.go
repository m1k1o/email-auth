package page

import (
	"html/template"
	"net/http"
	"os"

	"github.com/m1k1o/email-auth/internal/config"

	"github.com/rs/zerolog/log"
)

type Template struct {
	AppName   string
	AppUrl    string
	LoginUrl  string
	TargetUrl string
	Success   string
	Error     string
	LoggedIn  bool
	LoginBtn  bool
}

type Manager struct {
	app  config.App
	tmpl *template.Template
}

func New(templatePath string, app config.App) (*Manager, error) {
	html, err := os.ReadFile(templatePath)
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

func (manager *Manager) Error(w http.ResponseWriter, r *http.Request, msg string, code int) {
	w.WriteHeader(code)

	redirectTo := r.URL.Query().Get("to")
	manager.serve(w, Template{
		AppName: manager.app.Name,
		AppUrl:  manager.app.GetUrl(redirectTo),
		Error:   msg,
	})
}

func (manager *Manager) Success(w http.ResponseWriter, r *http.Request, msg string) {
	w.WriteHeader(http.StatusOK)

	redirectTo := r.URL.Query().Get("to")
	manager.serve(w, Template{
		AppName: manager.app.Name,
		AppUrl:  manager.app.GetUrl(redirectTo),
		Success: msg,
	})
}

func (manager *Manager) Login(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)

	redirectTo := r.URL.Query().Get("to")
	if redirectTo == "" {
		redirectTo = r.Referer()
	}

	loginUrl := ""
	if len(manager.app.Users) > 0 {
		var err error
		loginUrl, err = manager.app.GetLoginUrl(redirectTo)
		if err != nil {
			log.Err(err).Msg("error while generating login URL")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}

	manager.serve(w, Template{
		AppName:  manager.app.Name,
		AppUrl:   manager.app.GetUrl(redirectTo),
		LoginUrl: loginUrl,
	})
}

func (manager *Manager) LoggedIn(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	redirectTo := r.URL.Query().Get("to")
	manager.serve(w, Template{
		AppName:   manager.app.Name,
		AppUrl:    manager.app.GetUrl(redirectTo),
		LoggedIn:  true,
		TargetUrl: manager.app.Target,
	})
}

func (manager *Manager) LoginBtn(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	redirectTo := r.URL.Query().Get("to")
	token := r.URL.Query().Get("token")

	tokenUrl, err := manager.app.GetTokenUrl(token, redirectTo)
	if err != nil {
		log.Err(err).Msg("error while generating login URL")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	manager.serve(w, Template{
		AppName:  manager.app.Name,
		AppUrl:   tokenUrl,
		LoginBtn: true,
	})
}
