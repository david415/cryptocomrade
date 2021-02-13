package x448

import (
	"crypto/rand"
	"testing"

	"github.com/awnumar/memguard"
	"github.com/cloudflare/circl/dh/x448"
	"github.com/stretchr/testify/require"
)

func TestX448(t *testing.T) {
	alicePrivate, err := memguard.NewBufferFromReader(rand.Reader, x448.Size)
	require.NoError(t, err)
	var aliceSecret x448.Key
	copy(aliceSecret[:], alicePrivate.Bytes())
	var alicePublic x448.Key
	x448.KeyGen(&alicePublic, &aliceSecret)

	bobPrivate, err := memguard.NewBufferFromReader(rand.Reader, x448.Size)
	require.NoError(t, err)
	var bobSecret x448.Key
	copy(bobSecret[:], bobPrivate.Bytes())
	var bobPublic x448.Key
	x448.KeyGen(&bobPublic, &bobSecret)

	// Deriving Alice's shared key
	var aliceSharedSecret x448.Key
	ok := x448.Shared(&aliceSharedSecret, &aliceSecret, &bobPublic)
	require.True(t, ok)

	// Deriving Bob's shared key
	var bobSharedSecret x448.Key
	ok = x448.Shared(&bobSharedSecret, &bobSecret, &alicePublic)
	require.True(t, ok)

	// Shared secrets are equal, of course.
	require.Equal(t, bobSharedSecret, aliceSharedSecret)
}
