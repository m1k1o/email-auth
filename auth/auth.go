package auth

import (
	"sync"
	"time"
)

type Profile struct {
	Email string
}

type Session struct {
	profile  Profile
	token    string
	secret   string
	expires  time.Time
	loggedIn bool
}

func (s *Session) Profile() Profile {
	return s.profile
}

func (s *Session) Token() string {
	return s.token
}

func (s *Session) Secret() string {
	return s.secret
}

func (s *Session) Expired() bool {
	return time.Now().After(s.expires)
}

func (s *Session) LoggedIn() bool {
	return s.loggedIn
}

type Manager struct {
	mu sync.Mutex

	config Config

	tokens  map[string]*Session
	secrets map[string]*Session
}

func New(config Config) *Manager {
	return &Manager{
		config:  config,
		tokens:  map[string]*Session{},
		secrets: map[string]*Session{},
	}
}

func (manager *Manager) GetByToken(token string) (*Session, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	session, ok := manager.tokens[token]
	return session, ok
}

func (manager *Manager) GetBySecret(secret string) (*Session, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	session, ok := manager.secrets[secret]
	return session, ok
}

func (manager *Manager) Create(profile Profile) *Session {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	token := randomString(16)
	secret := randomString(16)

	session := &Session{
		profile:  profile,
		token:    token,
		secret:   secret,
		expires:  time.Now().Add(manager.config.Expiration),
		loggedIn: false,
	}

	manager.secrets[secret] = session
	return session
}

func (manager *Manager) Login(session *Session) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	session.loggedIn = true
	manager.tokens[session.token] = session
}

func (manager *Manager) Delete(session *Session) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	delete(manager.tokens, session.token)
	delete(manager.secrets, session.secret)
}
