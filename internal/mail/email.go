package mail

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/url"

	"gopkg.in/mail.v2"

	"email-proxy-auth/internal/auth"
)

type Manager struct {
	config Config
	tmpl   *template.Template
}

func New(config Config) (*Manager, error) {
	html, err := ioutil.ReadFile(config.TemplatePath)
	if err != nil {
		return nil, err
	}

	tmpl, err := template.New("login-email").Parse(string(html))
	if err != nil {
		return nil, err
	}

	return &Manager{
		config: config,
		tmpl:   tmpl,
	}, nil
}

func (manager *Manager) getLoginLink(session *auth.Session, redirectTo string) (string, error) {
	loginLink, err := url.Parse(manager.config.App.Url)
	if err != nil {
		return "", err
	}

	q := loginLink.Query()
	q.Add("login", session.Secret())
	if redirectTo != "" {
		q.Add("to", redirectTo)
	}
	loginLink.RawQuery = q.Encode()

	return loginLink.String(), nil
}

func (manager *Manager) getBody(session *auth.Session, redirectTo string) (string, error) {
	loginLink, err := manager.getLoginLink(session, redirectTo)
	if err != nil {
		return "", err
	}

	data := struct {
		AppName   string
		LoginLink string
	}{
		AppName:   manager.config.App.Name,
		LoginLink: loginLink,
	}

	var body bytes.Buffer
	err = manager.tmpl.Execute(&body, data)
	if err != nil {
		return "", err
	}

	return body.String(), err
}

func (manager *Manager) Send(session *auth.Session, redirectTo string) error {
	m := mail.NewMessage()

	// Set E-Mail sender
	m.SetHeader("From", manager.config.Email.From)

	// Set E-Mail receivers
	m.SetHeader("To", session.Profile().Email)

	// Set E-Mail subject
	m.SetHeader("Subject", fmt.Sprintf("Login to %s", manager.config.App.Name))

	// Get E-mail body
	body, err := manager.getBody(session, redirectTo)
	if err != nil {
		return err
	}

	// Set E-Mail body
	m.SetBody("text/html", body)

	// Settings for SMTP server
	d := mail.NewDialer(manager.config.Email.Host, manager.config.Email.Port, manager.config.Email.Username, manager.config.Email.Password)

	// This is only needed when SSL/TLS certificate is not valid on server.
	// In production this should be set to false.
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	// Now send E-Mail
	return d.DialAndSend(m)
}
