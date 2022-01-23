package mail

type Config struct {
	AppName      string
	AppUrl       string
	TemplatePath string
	FromAddress  string

	// smtp
	Host     string
	Port     int
	Username string
	Password string
}
