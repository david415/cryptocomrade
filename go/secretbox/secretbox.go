package secretbox

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	nonceSize = 24
)

var (
	errOpen = errors.New("failed to open envelope")
)

// SecretKey encapsulates a secret key so that it can be used
// in AEAD cipher operations methods: Open and Seal.
type SecretKey struct {
	key *[32]byte
}

// Load loads a SecretKey.
func Load(b *[32]byte) *SecretKey {
	return &SecretKey{
		key: b,
	}
}

// New returns a new SecretKey.
func New() *SecretKey {
	b := [32]byte{}
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	return &SecretKey{
		key: &b,
	}
}

// Bytes returns the secret key as a byte slice.
func (s *SecretKey) Bytes() []byte {
	return s.key[:]
}

// Open decrypts the ciphertext and returns the plaintext or an error.
func (s *SecretKey) Open(ciphertext []byte) ([]byte, error) {
	nonce := [24]byte{}
	copy(nonce[:], ciphertext[:nonceSize])
	out, ok := secretbox.Open(nil, ciphertext[nonceSize:], &nonce, s.key)
	if !ok {
		return nil, errOpen
	}
	return out, nil
}

// Seal encrypts the plaintext and returns the ciphertext.
func (s *SecretKey) Seal(plaintext []byte) []byte {
	nonce := [24]byte{}
	_, err := rand.Read(nonce[:])
	if err != nil {
		panic(err)
	}
	out := make([]byte, nonceSize)
	copy(out, nonce[:])
	ciphertext := secretbox.Seal(out, plaintext, &nonce, s.key)
	return ciphertext
}
