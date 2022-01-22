package auth

import (
	"fmt"
	"math/rand"
)

func randomString(size int) string {
	b := make([]byte, size)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
