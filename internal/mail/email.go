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
	"email-proxy-auth/internal/config"
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

	// Now send E-Mail
	return Send(manager.config.Email, m)
}

func Send(config config.Email, message *mail.Message) error {
	dialer := mail.NewDialer(config.Host, config.Port, config.Username, config.Password)

	// This is only needed when SSL/TLS certificate is not valid on server.
	// In production this should be set to false.
	dialer.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	return dialer.DialAndSend(message)
}

func Test(config config.Email, toEmail string) error {
	m := mail.NewMessage()

	// Set E-Mail sender
	m.SetHeader("From", config.From)

	// Set E-Mail receivers
	m.SetHeader("To", toEmail)

	// Set E-Mail subject
	m.SetHeader("Subject", "Test email from E-Mail proxy auth")

	// Set E-Mail body
	m.SetBody("text/plain", "If you see this in your inbox, that means the test was successful.")

	// Now send E-Mail
	return Send(config, m)
}
