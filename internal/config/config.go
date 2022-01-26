package config

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

//
// app
//

type Header struct {
	Enabled bool
	Name    string
}

type Expiration struct {
	LoginLink time.Duration
	Session   time.Duration
}

type App struct {
	Name   string
	Url    string
	Bind   string
	Proxy  bool
	Auths  map[string]string
	Emails []string

	Header     Header
	Expiration Expiration
}

func (c *App) GetUrl(r *http.Request) string {
	redirectTo := r.URL.Query().Get("to")

	if redirectTo == "" {
		redirectTo = r.Referer()
	}

	url, err := c.CreateUrl("", redirectTo)
	if err != nil {
		return c.Url
	}

	return url
}

func (c *App) CreateUrl(token, redirectTo string) (string, error) {
	link, err := url.Parse(c.Url)
	if err != nil {
		return "", err
	}

	q := link.Query()
	if redirectTo != "" {
		q.Add("token", token)
	}
	if redirectTo != "" {
		q.Add("to", redirectTo)
	}
	link.RawQuery = q.Encode()

	return link.String(), nil
}

func (App) Init(cmd *cobra.Command) error {
	cmd.PersistentFlags().String("app.name", "E-mail proxy auth", "Application Name.")
	if err := viper.BindPFlag("app.name", cmd.PersistentFlags().Lookup("app.name")); err != nil {
		return err
	}

	cmd.PersistentFlags().String("app.url", "http://127.0.0.1:8080/", "Application URL.")
	if err := viper.BindPFlag("app.url", cmd.PersistentFlags().Lookup("app.url")); err != nil {
		return err
	}

	cmd.PersistentFlags().String("app.bind", "127.0.0.1:8080", "Address, where is HTTP server listening.")
	if err := viper.BindPFlag("app.bind", cmd.PersistentFlags().Lookup("app.bind")); err != nil {
		return err
	}

	cmd.PersistentFlags().Bool("app.proxy", false, "Trust proxy X-Forwarded-For and X-Real-Ip headers.")
	if err := viper.BindPFlag("app.proxy", cmd.PersistentFlags().Lookup("app.proxy")); err != nil {
		return err
	}

	cmd.PersistentFlags().StringSlice("app.emails", []string{}, "Allowed email addresses or domains (only @domain.org) to log in.")
	if err := viper.BindPFlag("app.emails", cmd.PersistentFlags().Lookup("app.emails")); err != nil {
		return err
	}

	//
	// header
	//

	cmd.PersistentFlags().Bool("app.header.enabled", true, "If authentication header should be enabled.")
	if err := viper.BindPFlag("app.header.enabled", cmd.PersistentFlags().Lookup("app.header.enabled")); err != nil {
		return err
	}

	cmd.PersistentFlags().String("app.header.name", "X-Auth-Email", "Authentication header name.")
	if err := viper.BindPFlag("app.header.name", cmd.PersistentFlags().Lookup("app.header.name")); err != nil {
		return err
	}

	//
	// expiration
	//

	cmd.PersistentFlags().Int64("app.expiration.link", 300, "Login link expiration in seconds.") // 5 min
	if err := viper.BindPFlag("app.expiration.link", cmd.PersistentFlags().Lookup("app.expiration.link")); err != nil {
		return err
	}

	cmd.PersistentFlags().Int64("app.expiration.session", 1209600, "Session expiration in seconds.") // 14 days
	if err := viper.BindPFlag("app.expiration.session", cmd.PersistentFlags().Lookup("app.expiration.session")); err != nil {
		return err
	}

	return nil
}

func (c *App) Set() {
	c.Name = viper.GetString("app.name")
	c.Url = viper.GetString("app.url")
	c.Bind = viper.GetString("app.bind")
	c.Proxy = viper.GetBool("app.proxy")
	c.Auths = viper.GetStringMapString("app.auths")
	c.Emails = viper.GetStringSlice("app.emails")

	c.Header.Enabled = viper.GetBool("app.header.enabled")
	c.Header.Name = viper.GetString("app.header.name")

	c.Expiration.LoginLink = time.Duration(viper.GetInt64("app.expiration.link")) * time.Second
	c.Expiration.Session = time.Duration(viper.GetInt64("app.expiration.session")) * time.Second
}

//
// tmpl
//

type Tmpl struct {
	Page  string
	Email string
}

func (Tmpl) Init(cmd *cobra.Command) error {
	cmd.PersistentFlags().String("tmpl.page", "./tmpl/page.html", "Template path for web page.")
	if err := viper.BindPFlag("tmpl.page", cmd.PersistentFlags().Lookup("tmpl.page")); err != nil {
		return err
	}

	cmd.PersistentFlags().String("tmpl.email", "./tmpl/email.html", "Template path for email.")
	if err := viper.BindPFlag("tmpl.email", cmd.PersistentFlags().Lookup("tmpl.email")); err != nil {
		return err
	}

	return nil
}

func (c *Tmpl) Set() {
	c.Page = viper.GetString("tmpl.page")
	c.Email = viper.GetString("tmpl.email")
}

//
// email
//

type Email struct {
	From string

	// smtp
	Host     string
	Port     int
	Username string
	Password string
}

func (Email) Init(cmd *cobra.Command) error {
	cmd.PersistentFlags().String("email.from", "admin@localhost", "Email from address.")
	if err := viper.BindPFlag("email.from", cmd.PersistentFlags().Lookup("email.from")); err != nil {
		return err
	}

	cmd.PersistentFlags().String("email.host", "127.0.0.1", "Email SMTP host.")
	if err := viper.BindPFlag("email.host", cmd.PersistentFlags().Lookup("email.host")); err != nil {
		return err
	}

	cmd.PersistentFlags().Int("email.port", 25, "Email SMTP port.")
	if err := viper.BindPFlag("email.port", cmd.PersistentFlags().Lookup("email.port")); err != nil {
		return err
	}

	cmd.PersistentFlags().String("email.username", "", "Email SMTP username.")
	if err := viper.BindPFlag("email.username", cmd.PersistentFlags().Lookup("email.username")); err != nil {
		return err
	}

	cmd.PersistentFlags().String("email.password", "", "Email SMTP password.")
	if err := viper.BindPFlag("email.password", cmd.PersistentFlags().Lookup("email.password")); err != nil {
		return err
	}

	return nil
}

func (c *Email) Set() {
	c.From = viper.GetString("email.from")
	c.Host = viper.GetString("email.host")
	c.Port = viper.GetInt("email.port")
	c.Username = viper.GetString("email.username")
	c.Password = viper.GetString("email.password")
}

//
// cookie
//

type Cookie struct {
	Name       string
	Domain     string
	Secure     bool
	HttpOnly   bool
	Expiration time.Duration
}

func (Cookie) Init(cmd *cobra.Command) error {
	cmd.PersistentFlags().String("cookie.name", "MAILSESSION", "Cookie name.")
	if err := viper.BindPFlag("cookie.name", cmd.PersistentFlags().Lookup("cookie.name")); err != nil {
		return err
	}

	cmd.PersistentFlags().String("cookie.domain", "", "Associated domain with the cookie.")
	if err := viper.BindPFlag("cookie.domain", cmd.PersistentFlags().Lookup("cookie.domain")); err != nil {
		return err
	}

	cmd.PersistentFlags().Bool("cookie.secure", true, "A cookie with the Secure attribute is only sent to the server with an encrypted request over the HTTPS protocol.")
	if err := viper.BindPFlag("cookie.secure", cmd.PersistentFlags().Lookup("cookie.secure")); err != nil {
		return err
	}

	cmd.PersistentFlags().Bool("cookie.httponly", true, "A cookie with the HttpOnly attribute is inaccessible to the JavaScript Document.cookie API; it's only sent to the server.")
	if err := viper.BindPFlag("cookie.httponly", cmd.PersistentFlags().Lookup("cookie.httponly")); err != nil {
		return err
	}

	return nil
}

func (c *Cookie) Set() {
	c.Name = viper.GetString("cookie.name")
	c.Domain = viper.GetString("cookie.domain")
	c.Secure = viper.GetBool("cookie.secure")
	c.HttpOnly = viper.GetBool("cookie.httponly")
}

//
// redis
//

type Redis struct {
	Enabled  bool
	Addr     string
	Password string
	Database int
}

func (Redis) Init(cmd *cobra.Command) error {
	cmd.PersistentFlags().Bool("redis.enabled", false, "If redis should be used or not.")
	if err := viper.BindPFlag("redis.enabled", cmd.PersistentFlags().Lookup("redis.enabled")); err != nil {
		return err
	}

	cmd.PersistentFlags().String("redis.host", "127.0.0.1", "Redis host.")
	if err := viper.BindPFlag("redis.host", cmd.PersistentFlags().Lookup("redis.host")); err != nil {
		return err
	}

	cmd.PersistentFlags().Int("redis.port", 6379, "Redis port.")
	if err := viper.BindPFlag("redis.port", cmd.PersistentFlags().Lookup("redis.port")); err != nil {
		return err
	}

	cmd.PersistentFlags().String("redis.password", "", "Redis password.")
	if err := viper.BindPFlag("redis.password", cmd.PersistentFlags().Lookup("redis.password")); err != nil {
		return err
	}

	cmd.PersistentFlags().Int("redis.database", 0, "Redis database.")
	if err := viper.BindPFlag("redis.database", cmd.PersistentFlags().Lookup("redis.database")); err != nil {
		return err
	}

	return nil
}

func (c *Redis) Set() {
	c.Enabled = viper.GetBool("redis.enabled")
	c.Addr = fmt.Sprintf("%s:%d", viper.GetString("redis.host"), viper.GetInt("redis.port"))
	c.Password = viper.GetString("redis.password")
	c.Database = viper.GetInt("redis.database")
}
