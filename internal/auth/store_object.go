package auth

import (
	"sync"
	"time"

	"github.com/m1k1o/email-auth/internal/config"
)

type storeObject struct {
	sync.Mutex
	sessions   map[string]*Session
	expiration *config.Expiration
}

func NewStoreObject(expiration *config.Expiration) *storeObject {
	return &storeObject{
		sessions:   map[string]*Session{},
		expiration: expiration,
	}
}

func (s *storeObject) Get(token string) (*Session, error) {
	s.Lock()
	defer s.Unlock()

	session, ok := s.sessions[token]
	if ok {
		return session, nil
	}

	return nil, ErrTokenNotFound
}

func (s *storeObject) Add(email string) (string, error) {
	s.Lock()
	defer s.Unlock()

	token := randomString(16)
	s.sessions[token] = &Session{
		email:    email,
		expires:  time.Now().Add(s.expiration.LoginLink),
		loggedIn: false,
	}

	return token, nil
}

func (s *storeObject) Login(token string) (string, error) {
	s.Lock()
	defer s.Unlock()

	session := s.sessions[token]
	if session.loggedIn {
		return "", ErrAlreadyLoggedIn
	}

	session.loggedIn = true
	session.expires = session.expires.Add(s.expiration.Session)
	delete(s.sessions, token)

	token = randomString(16)
	s.sessions[token] = session
	return token, nil
}

func (s *storeObject) Delete(token string) error {
	s.Lock()
	defer s.Unlock()

	delete(s.sessions, token)
	return nil
}
