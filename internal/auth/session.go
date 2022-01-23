package auth

import "time"

type Session struct {
	email    string
	expires  time.Time
	loggedIn bool
}

func (s *Session) Email() string {
	return s.email
}

func (s *Session) Expired() bool {
	return time.Now().After(s.expires)
}

func (s *Session) LoggedIn() bool {
	return s.loggedIn
}
