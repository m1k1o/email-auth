package auth

import (
	"fmt"

	"github.com/rs/zerolog/log"

	"github.com/m1k1o/email-auth/internal/config"
)

var (
	ErrTokenNotFound   = fmt.Errorf("token not found")
	ErrAlreadyLoggedIn = fmt.Errorf("already logged in")
)

type Store interface {
	Get(token string) (*Session, error)
	Add(email string) (string, error)
	Login(token string) (string, error)
	Delete(token string) error
}

func NewStore(config config.Redis, expiration config.Expiration) Store {
	if config.Enabled {
		log.Info().Msgf("using redis on %s", config.Addr)
		return NewStoreRedis(config, expiration)
	} else {
		log.Info().Msg("using object storage")
		return NewStoreObject(expiration)
	}
}
