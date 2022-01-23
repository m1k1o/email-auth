package auth

import "fmt"

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
