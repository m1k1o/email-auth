package auth

import (
	"context"
	"email-proxy-auth/internal/config"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
)

type storeRedis struct {
	sync.Mutex
	client     *redis.Client
	expiration time.Duration
}

func NewStoreRedis(config config.Redis, expiration time.Duration) *storeRedis {
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

func (s *storeRedis) set(session *Session) (string, error) {
	token := randomString(16)

	val, err := session.serialize()
	if err != nil {
		return "", err
	}

	err = s.client.Set(context.Background(), token, val, s.expiration).Err()
	return token, err
}

func (s *storeRedis) Add(email string) (string, error) {
	s.Lock()
	defer s.Unlock()

	return s.set(&Session{
		email:    email,
		expires:  time.Now().Add(s.expiration),
		loggedIn: false,
	})
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

	if err := s.del(token); err != nil {
		return "", ErrAlreadyLoggedIn
	}

	return s.set(session)
}

func (s *storeRedis) del(token string) error {
	return s.client.Del(context.Background(), token).Err()
}

func (s *storeRedis) Delete(token string) error {
	s.Lock()
	defer s.Unlock()

	return s.del(token)
}
