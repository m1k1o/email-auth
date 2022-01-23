package auth

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

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

func (s *Session) deserialize(val string) error {
	x := strings.Index(val, "|")

	if x == -1 || (val[0] != 'Y' && val[0] != 'N') {
		return fmt.Errorf("wrong format")
	}

	// if logged in
	s.loggedIn = val[0] == 'Y'

	// expiration time
	i, err := strconv.ParseInt(val[1:x], 10, 64)
	if err != nil {
		return err
	}
	s.expires = time.Unix(i, 0)

	// email
	s.email = val[x+1:]
	return nil
}

func (s *Session) serialize() (string, error) {
	loggedIn := "N"
	if s.loggedIn {
		loggedIn = "Y"
	}

	return fmt.Sprintf("%s%d|%s", loggedIn, s.expires.Unix(), s.email), nil
}
