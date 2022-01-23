package auth

import (
	"sync"
	"time"
)

type storeObject struct {
	sync.Mutex
	sessions   map[string]*Session
	expiration time.Duration
}

func NewStoreObject(expiration time.Duration) *storeObject {
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
		expires:  time.Now().Add(s.expiration),
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
