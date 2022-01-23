package config

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

//
// app
//

type App struct {
	Name   string
	Url    string
	Bind   string
	Emails []string
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

	cmd.PersistentFlags().StringSlice("app.emails", []string{}, "Allowed E-Mail addresses or domains (only @domain.org) to log in.")
	if err := viper.BindPFlag("app.emails", cmd.PersistentFlags().Lookup("app.emails")); err != nil {
		return err
	}

	return nil
}

func (c *App) Set() {
	c.Name = viper.GetString("app.name")
	c.Url = viper.GetString("app.url")
	c.Bind = viper.GetString("app.bind")
	c.Emails = viper.GetStringSlice("app.emails")
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

	cmd.PersistentFlags().Int("cookie.expiration", 24*31, "Cookie & session expiration in hours.")
	if err := viper.BindPFlag("cookie.expiration", cmd.PersistentFlags().Lookup("cookie.expiration")); err != nil {
		return err
	}

	return nil
}

func (c *Cookie) Set() {
	c.Name = viper.GetString("cookie.name")
	c.Domain = viper.GetString("cookie.domain")
	c.Secure = viper.GetBool("cookie.secure")
	c.HttpOnly = viper.GetBool("cookie.httponly")
	c.Expiration = time.Duration(viper.GetInt("cookie.expiration")) * time.Hour
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

	cmd.PersistentFlags().String("redis.addr", "127.0.0.1:6379", "Redis address.")
	if err := viper.BindPFlag("redis.addr", cmd.PersistentFlags().Lookup("redis.addr")); err != nil {
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
	c.Addr = viper.GetString("redis.addr")
	c.Password = viper.GetString("redis.password")
	c.Database = viper.GetInt("redis.database")
}
