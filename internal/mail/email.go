package mail

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"io/ioutil"

	"gopkg.in/mail.v2"

	"email-proxy-auth/internal/config"
)

type Manager struct {
	app   config.App
	email config.Email
	tmpl  *template.Template
}

func New(templatePath string, app config.App, email config.Email) (*Manager, error) {
	html, err := ioutil.ReadFile(templatePath)
	if err != nil {
		return nil, err
	}

	tmpl, err := template.New("login-email").Parse(string(html))
	if err != nil {
		return nil, err
	}

	return &Manager{
		app:   app,
		email: email,
		tmpl:  tmpl,
	}, nil
}

func (manager *Manager) getBody(loginLink string) (string, error) {
	data := struct {
		AppName   string
		LoginLink string
	}{
		AppName:   manager.app.Name,
		LoginLink: loginLink,
	}

	var body bytes.Buffer
	err := manager.tmpl.Execute(&body, data)
	if err != nil {
		return "", err
	}

	return body.String(), err
}

func (manager *Manager) Send(email, token, redirectTo string) error {
	m := mail.NewMessage()

	// Set email sender
	m.SetHeader("From", manager.email.From)

	// Set email receivers
	m.SetHeader("To", email)

	// Set email subject
	m.SetHeader("Subject", fmt.Sprintf("Login to %s", manager.app.Name))

	// Get login link
	loginLink, err := manager.app.CreateUrl(token, redirectTo)
	if err != nil {
		return err
	}

	// Get email body
	body, err := manager.getBody(loginLink)
	if err != nil {
		return err
	}

	// Set email body
	m.SetBody("text/html", body)

	// Now send email
	return Send(manager.email, m)
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

	// Set email sender
	m.SetHeader("From", config.From)

	// Set email receivers
	m.SetHeader("To", toEmail)

	// Set email subject
	m.SetHeader("Subject", "Test email from email proxy auth")

	// Set email body
	m.SetBody("text/plain", "If you see this in your inbox, that means the test was successful.")

	// Now send email
	return Send(config, m)
}
