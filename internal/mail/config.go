package mail

import "email-proxy-auth/internal/config"

type Config struct {
	TemplatePath string

	App   config.App
	Email config.Email
}
