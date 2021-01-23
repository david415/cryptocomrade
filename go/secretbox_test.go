package cryptocomrade

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecretKey(t *testing.T) {
	secretKey := New()
	plaintext1 := []byte("hello world")
	ciphertext := secretKey.Seal(plaintext1)
	plaintext2, err := secretKey.Open(ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext1, plaintext2)
}
