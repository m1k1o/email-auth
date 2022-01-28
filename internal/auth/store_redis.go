package auth

import (
	"context"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"

	"email-proxy-auth/internal/config"
)

type storeRedis struct {
	sync.Mutex
	client     *redis.Client
	expiration config.Expiration
}

func NewStoreRedis(config config.Redis, expiration config.Expiration) *storeRedis {
	return &storeRedis{
		client: redis.NewClient(&redis.Options{
			Addr:     config.Addr,
			Password: config.Password,
			DB:       config.Database,
		}),
		expiration: expiration,
	}
}

func (s *storeRedis) get(token string) (*Session, error) {
	val, err := s.client.Get(context.Background(), token).Result()
	if err == redis.Nil {
		return nil, ErrTokenNotFound
	} else if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	session := &Session{}
	if err := session.deserialize(val); err != nil {
		return nil, err
	}

	return session, nil
}

func (s *storeRedis) Get(token string) (*Session, error) {
	s.Lock()
	defer s.Unlock()

	return s.get(token)
}

func (s *storeRedis) set(session *Session, expiration time.Duration) (string, error) {
	token := randomString(16)

	val, err := session.serialize()
	if err != nil {
		return "", err
	}

	err = s.client.Set(context.Background(), token, val, expiration).Err()
	return token, err
}

func (s *storeRedis) Add(email string) (string, error) {
	s.Lock()
	defer s.Unlock()

	return s.set(&Session{
		email:    email,
		expires:  time.Now().Add(s.expiration.LoginLink),
		loggedIn: false,
	}, s.expiration.LoginLink)
}

func (s *storeRedis) Login(token string) (string, error) {
	s.Lock()
	defer s.Unlock()

	session, err := s.get(token)
	if err != nil {
		return "", err
	}

	if session.loggedIn {
		return "", ErrAlreadyLoggedIn
	}

	session.loggedIn = true
	session.expires = session.expires.Add(s.expiration.Session)

	if err := s.del(token); err != nil {
		return "", err
	}

	return s.set(session, s.expiration.Session)
}

func (s *storeRedis) del(token string) error {
	return s.client.Del(context.Background(), token).Err()
}

func (s *storeRedis) Delete(token string) error {
	s.Lock()
	defer s.Unlock()

	return s.del(token)
}
