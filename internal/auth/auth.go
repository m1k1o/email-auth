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
	expires  time.Time
	loggedIn bool
}

func (s *Session) Profile() Profile {
	return s.profile
}

func (s *Session) Token() string {
	return s.token
}

func (s *Session) Expired() bool {
	return time.Now().After(s.expires)
}

func (s *Session) LoggedIn() bool {
	return s.loggedIn
}

type Manager struct {
	mu sync.Mutex

	config   Config
	sessions map[string]*Session
}

func New(config Config) *Manager {
	return &Manager{
		config:   config,
		sessions: map[string]*Session{},
	}
}

func (manager *Manager) Get(token string) (*Session, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	session, ok := manager.sessions[token]
	return session, ok
}

func (manager *Manager) Create(profile Profile) *Session {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	token := randomString(16)

	session := &Session{
		profile:  profile,
		token:    token,
		expires:  time.Now().Add(manager.config.Expiration),
		loggedIn: false,
	}

	manager.sessions[token] = session
	return session
}

func (manager *Manager) Login(session *Session) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	delete(manager.sessions, session.token)
	session.token = randomString(16)
	manager.sessions[session.token] = session

	session.loggedIn = true
}

func (manager *Manager) Delete(session *Session) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	delete(manager.sessions, session.token)
}
