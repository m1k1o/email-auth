package mail

type Config struct {
	AppName      string
	BaseUrl      string
	TemplatePath string
	FromAddress  string

	// smtp
	Host     string
	Port     int
	Username string
	Password string
}
