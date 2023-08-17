package gui

import (
	_ "embed"
	"html/template"
	"net/http"
	"sort"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/m1k1o/email-auth/internal/config"
)

//go:embed index.gohtml
var indexHtml string

//go:embed emails.gohtml
var emailsHtml string

//go:embed users.gohtml
var usersHtml string

type Manager struct {
	app    config.App
	config config.Gui
	mux    *http.ServeMux
}

func New(app config.App, config config.Gui) (*Manager, error) {
	return &Manager{
		app:    app,
		config: config,
		mux:    http.NewServeMux(),
	}, nil
}

func (m *Manager) Init() error {
	// CRUD
	m.mux.HandleFunc("/", m.index)
	m.mux.HandleFunc("/emails", m.listEmails)
	m.mux.HandleFunc("/email", m.editEmail)
	m.mux.HandleFunc("/users", m.listUsers)
	m.mux.HandleFunc("/user", m.editUser)
	return nil
}

func (m *Manager) index(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("index-page").Parse(indexHtml)
	if err != nil {
		log.Err(err).Msg("error while parsing template")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		log.Err(err).Msg("error while serving page")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (m *Manager) listEmails(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("emails-page").Parse(emailsHtml)
	if err != nil {
		log.Err(err).Msg("error while parsing template")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	emails := m.app.Emails
	sort.Strings(emails)

	err = tmpl.Execute(w, struct {
		Emails []string
	}{
		Emails: emails,
	})
	if err != nil {
		log.Err(err).Msg("error while serving page")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (m *Manager) editEmail(w http.ResponseWriter, r *http.Request) {
	// parse body as html form
	err := r.ParseForm()
	if err != nil {
		log.Error().Err(err).Msg("unable to parse form")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	email := r.Form.Get("email")
	if email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}

	action := r.Form.Get("action")
	if action == "" {
		http.Error(w, "action is required", http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	backups := m.app.Emails

	if action == "add" {
		// add email
		m.app.Emails = append(m.app.Emails, email)
	} else if action == "remove" {
		// remove email
		emails := m.app.Emails
		for i, e := range emails {
			if e == email {
				m.app.Emails = append(emails[:i], emails[i+1:]...)
				break
			}
		}
	} else {
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}

	// save changes
	err = m.app.SaveEmails()
	if err != nil {
		log.Error().Err(err).Msg("unable to save emails")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		// restore backup
		m.app.Emails = backups
		return
	}

	// write metatag to rerirect page to ./emails
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<meta http-equiv=\"refresh\" content=\"0; url=./emails\" />"))
}

func (m *Manager) listUsers(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("users-page").Parse(usersHtml)
	if err != nil {
		log.Err(err).Msg("error while parsing template")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	var users []string
	for user := range m.app.Users {
		users = append(users, user)
	}

	sort.Strings(users)

	err = tmpl.Execute(w, struct {
		Users []string
	}{
		Users: users,
	})
	if err != nil {
		log.Err(err).Msg("error while serving page")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (m *Manager) editUser(w http.ResponseWriter, r *http.Request) {
	// parse body as html form
	err := r.ParseForm()
	if err != nil {
		log.Error().Err(err).Msg("unable to parse form")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user := r.Form.Get("user")
	if user == "" {
		http.Error(w, "user is required", http.StatusBadRequest)
		return
	}

	password := r.Form.Get("password")
	if password == "" && r.Method == http.MethodPut {
		http.Error(w, "password is required", http.StatusBadRequest)
		return
	}

	action := r.Form.Get("action")
	if action == "" {
		http.Error(w, "action is required", http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bak := m.app.Users[user]

	if action == "add" {
		// create hash
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Error().Err(err).Msg("unable to generate hash")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// add user
		m.app.Users[user] = string(hash)
	} else if action == "remove" {
		// remove user
		delete(m.app.Users, user)
	} else {
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}

	// save changes
	err = m.app.SaveUsers()
	if err != nil {
		log.Error().Err(err).Msg("unable to save users")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		// restore backup
		m.app.Users[user] = bak
		return
	}

	// write metatag to rerirect page to ./users
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<meta http-equiv=\"refresh\" content=\"0; url=./users\" />"))
}

/*
// TODO: roles
func (m *Manager) editRoles(w http.ResponseWriter, r *http.Request) {
	// parse body as html form
	err := r.ParseForm()
	if err != nil {
		log.Error().Err(err).Msg("unable to parse form")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user := r.Form.Get("user")
	if user == "" {
		http.Error(w, "user is required", http.StatusBadRequest)
		return
	}

	role := r.Form.Get("role")
	if role == "" && r.Method == http.MethodPut {
		http.Error(w, "role is required", http.StatusBadRequest)
		return
	}

	action := r.Form.Get("action")
	if action == "" {
		http.Error(w, "action is required", http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	backup := m.app.Users[user]

	if action == "add" {
		// add user role
		m.app.Users[user] = role
	} else if action == "remove" {
		// remove user role
		delete(m.app.Users, user)
	} else {
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}

	// save changes
	err = m.app.SaveRoles()
	if err != nil {
		log.Error().Err(err).Msg("unable to save roles")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		// restore backup
		m.app.Users[user] = backup
		return
	}

	// write metatag to rerirect page to ./roles
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<meta http-equiv=\"refresh\" content=\"0; url=./roles\" />"))
}
*/

func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mux.ServeHTTP(w, r)
}
