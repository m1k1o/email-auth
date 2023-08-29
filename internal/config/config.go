package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

//
// app
//

type Header struct {
	Enabled bool
	Name    string
	Role    string
}

type Expiration struct {
	LoginLink time.Duration
	Session   time.Duration
}

type App struct {
	Name   string
	Url    string
	Target string
	Bind   string
	Proxy  bool

	// username:password
	Users     map[string]string
	usersFile string

	// list of emails or @domains
	Emails     []string
	emailsFile string

	// username/email:role
	Roles     map[string]string
	rolesFile string

	RedirectAllowlist []url.URL

	LoginBtn bool // do not login automatically but show login button instead

	Header     *Header
	Expiration *Expiration
}

func (c *App) GetUrl(redirectTo string) string {
	link, err := url.Parse(c.Url)
	if err != nil {
		return c.Url
	}

	q := link.Query()
	if redirectTo != "" {
		q.Add("to", redirectTo)
	}
	link.RawQuery = q.Encode()

	return link.String()
}

func (c *App) GetTokenUrl(token, redirectTo string) (string, error) {
	link, err := url.Parse(c.Url)
	if err != nil {
		return "", err
	}

	q := link.Query()
	q.Add("token", token)
	if redirectTo != "" {
		q.Add("to", redirectTo)
	}
	link.RawQuery = q.Encode()

	return link.String(), nil
}

func (c *App) GetLoginUrl(redirectTo string) (string, error) {
	link, err := url.Parse(c.Url)
	if err != nil {
		return "", err
	}

	q := link.Query()
	q.Add("login", "1")
	if redirectTo != "" {
		q.Add("to", redirectTo)
	}
	link.RawQuery = q.Encode()

	return link.String(), nil
}

func (App) Init(cmd *cobra.Command) error {
	cmd.PersistentFlags().String("app.name", "E-mail auth", "Application Name.")
	if err := viper.BindPFlag("app.name", cmd.PersistentFlags().Lookup("app.name")); err != nil {
		return err
	}

	cmd.PersistentFlags().String("app.url", "http://127.0.0.1:8080/", "Application URL.")
	if err := viper.BindPFlag("app.url", cmd.PersistentFlags().Lookup("app.url")); err != nil {
		return err
	}

	cmd.PersistentFlags().String("app.target", "", "Target URL that will be shown after logging in.")
	if err := viper.BindPFlag("app.target", cmd.PersistentFlags().Lookup("app.target")); err != nil {
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

	cmd.PersistentFlags().String("app.emails_file", "", "Path to a file, where additional emails are stored, deparated by newline.")
	if err := viper.BindPFlag("app.emails_file", cmd.PersistentFlags().Lookup("app.emails_file")); err != nil {
		return err
	}

	cmd.PersistentFlags().StringSlice("app.users", []string{}, "Users authentication using HTTP Basic Auth, with bcrypt hashes, in format user:hash.")
	if err := viper.BindPFlag("app.users", cmd.PersistentFlags().Lookup("app.users")); err != nil {
		return err
	}

	cmd.PersistentFlags().String("app.users_file", "", "Path to a file, where additional users are stored, deparated by newline.")
	if err := viper.BindPFlag("app.users_file", cmd.PersistentFlags().Lookup("app.users_file")); err != nil {
		return err
	}

	cmd.PersistentFlags().StringSlice("app.roles", []string{}, "Roles for users and emails, in format key=value.")
	if err := viper.BindPFlag("app.roles", cmd.PersistentFlags().Lookup("app.roles")); err != nil {
		return err
	}

	cmd.PersistentFlags().String("app.roles_file", "", "Path to a file, where additional roles are stored, deparated by newline.")
	if err := viper.BindPFlag("app.roles_file", cmd.PersistentFlags().Lookup("app.roles_file")); err != nil {
		return err
	}

	cmd.PersistentFlags().StringSlice("app.redirect_allowlist", []string{}, "Allowed redirect URLs.")
	if err := viper.BindPFlag("app.redirect_allowlist", cmd.PersistentFlags().Lookup("app.redirect_allowlist")); err != nil {
		return err
	}

	cmd.PersistentFlags().Bool("app.login_btn", false, "Show login button instead of automatic login.")
	if err := viper.BindPFlag("app.login_btn", cmd.PersistentFlags().Lookup("app.login_btn")); err != nil {
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

	cmd.PersistentFlags().String("app.header.role", "X-Auth-Role", "Authentication header role.")
	if err := viper.BindPFlag("app.header.role", cmd.PersistentFlags().Lookup("app.header.role")); err != nil {
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
	c.Target = viper.GetString("app.target")
	c.Bind = viper.GetString("app.bind")
	c.Proxy = viper.GetBool("app.proxy")

	// get emails from config
	emails := viper.GetStringSlice("app.emails")

	// load emails from a file
	c.emailsFile = viper.GetString("app.emails_file")
	if c.emailsFile != "" {
		emailsBytes, err := os.ReadFile(c.emailsFile)
		if err != nil {
			log.Panic().Err(err).Msgf("error opening emails file")
		}

		emails = append(emails,
			strings.Split(string(emailsBytes), "\n")...)
	}

	// get users from config
	users := viper.GetStringSlice("app.users")

	// load users from a file
	c.usersFile = viper.GetString("app.users_file")
	if c.usersFile != "" {
		usersBytes, err := os.ReadFile(c.usersFile)
		if err != nil {
			log.Panic().Err(err).Msgf("error opening users file")
		}

		users = append(users,
			strings.Split(string(usersBytes), "\n")...)
	}

	// get roles from config
	roles := viper.GetStringSlice("app.roles")

	// load roles from a file
	c.rolesFile = viper.GetString("app.roles_file")
	if c.rolesFile != "" {
		rolesBytes, err := os.ReadFile(c.rolesFile)
		if err != nil {
			log.Panic().Err(err).Msgf("error opening roles file")
		}

		roles = append(roles,
			strings.Split(string(rolesBytes), "\n")...)
	}

	// clean up emails
	c.Emails = []string{}
	for _, email := range emails {
		email := strings.TrimSpace(email)
		if email == "" {
			continue
		}

		c.Emails = append(c.Emails, email)
	}

	// convert users to a map
	c.Users = map[string]string{}
	for _, user := range users {
		user := strings.TrimSpace(user)
		if user == "" {
			continue
		}

		split := strings.Split(user, ":")
		if len(split) != 2 {
			log.Panic().Msgf("error parsing BasicUser: %v", user)
		}

		username, secret := split[0], split[1]
		c.Users[username] = secret
	}

	// convert roles to a map
	c.Roles = map[string]string{}
	for _, row := range roles {
		row := strings.TrimSpace(row)
		if row == "" {
			continue
		}

		split := strings.Split(row, "=")
		if len(split) != 2 {
			log.Panic().Msgf("error parsing role: %v", row)
		}

		user, role := strings.TrimSpace(split[0]), strings.TrimSpace(split[1])
		user = strings.ToLower(user)
		c.Roles[user] = role
	}

	log.Info().
		Int("emails", len(c.Emails)).
		Int("users", len(c.Users)).
		Int("roles", len(c.Roles)).
		Msgf("loaded emails, users and roles")

	urls := viper.GetStringSlice("app.redirect_allowlist")
	c.RedirectAllowlist = []url.URL{}
	for _, u := range urls {
		u := strings.TrimSpace(u)
		if u == "" {
			continue
		}

		parsed, err := url.Parse(u)
		if err != nil {
			log.Panic().Err(err).Msgf("error parsing redirect URL: %v", u)
		}

		c.RedirectAllowlist = append(c.RedirectAllowlist, *parsed)
	}

	c.LoginBtn = viper.GetBool("app.login_btn")

	c.Header.Enabled = viper.GetBool("app.header.enabled")
	c.Header.Name = viper.GetString("app.header.name")
	c.Header.Role = viper.GetString("app.header.role")

	c.Expiration.LoginLink = time.Duration(viper.GetInt64("app.expiration.link")) * time.Second
	c.Expiration.Session = time.Duration(viper.GetInt64("app.expiration.session")) * time.Second
}

func (c *App) SaveEmails() error {
	// if there is no emails file, we cannot save anything
	if c.emailsFile == "" {
		return fmt.Errorf("no emails file specified")
	}

	payload := []byte(strings.Join(c.Emails, "\n"))
	return os.WriteFile(c.emailsFile, payload, 0644)
}

func (c *App) SaveUsers() error {
	// if there is no users file, we cannot save anything
	if c.usersFile == "" {
		return fmt.Errorf("no users file specified")
	}

	users := []string{}
	for username, secret := range c.Users {
		users = append(users, fmt.Sprintf("%s:%s", username, secret))
	}

	payload := []byte(strings.Join(users, "\n"))
	return os.WriteFile(c.usersFile, payload, 0644)
}

func (c *App) SaveRoles() error {
	// if there is no roles file, we cannot save anything
	if c.rolesFile == "" {
		return fmt.Errorf("no roles file specified")
	}

	roles := []string{}
	for user, role := range c.Roles {
		roles = append(roles, fmt.Sprintf("%s=%s", user, role))
	}

	payload := []byte(strings.Join(roles, "\n"))
	return os.WriteFile(c.rolesFile, payload, 0644)
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

//
// gui
//

type Gui struct {
	Enabled bool
	Bind    string
}

func (Gui) Init(cmd *cobra.Command) error {
	cmd.PersistentFlags().Bool("gui.enabled", false, "If GUI should be enabled.")
	if err := viper.BindPFlag("gui.enabled", cmd.PersistentFlags().Lookup("gui.enabled")); err != nil {
		return err
	}

	cmd.PersistentFlags().String("gui.bind", "127.0.0.1:8081", "Address, where is HTTP server listening.")
	if err := viper.BindPFlag("gui.bind", cmd.PersistentFlags().Lookup("gui.bind")); err != nil {
		return err
	}

	return nil
}

func (c *Gui) Set() {
	c.Enabled = viper.GetBool("gui.enabled")
	c.Bind = viper.GetString("gui.bind")
}
