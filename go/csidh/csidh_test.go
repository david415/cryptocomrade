package csidh

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/dh/csidh"
	"github.com/stretchr/testify/require"
)

func TestCSIDH(t *testing.T) {

	// Alice
	alicePrivateKey := new(csidh.PrivateKey)
	err := csidh.GeneratePrivateKey(alicePrivateKey, rand.Reader)
	require.NoError(t, err)

	alicePublicKey := new(csidh.PublicKey)
	csidh.GeneratePublicKey(alicePublicKey, alicePrivateKey, rand.Reader)

	require.True(t, csidh.Validate(alicePublicKey, rand.Reader))

	// Bob
	bobPrivateKey := new(csidh.PrivateKey)
	err = csidh.GeneratePrivateKey(bobPrivateKey, rand.Reader)
	require.NoError(t, err)

	bobPublicKey := new(csidh.PublicKey)
	csidh.GeneratePublicKey(bobPublicKey, bobPrivateKey, rand.Reader)

	require.True(t, csidh.Validate(bobPublicKey, rand.Reader))

	// Alice sends her public key to Bob over an authenticated channel
	// and Bob computes their shared secret:
	bobSharedSecret := [64]byte{}
	require.True(t, csidh.DeriveSecret(&bobSharedSecret, alicePublicKey, bobPrivateKey, rand.Reader))

	// Bob sends his public key to Alice over an authenticated channel
	// and Alice computes their shared secret:
	aliceSharedSecret := [64]byte{}
	require.True(t, csidh.DeriveSecret(&aliceSharedSecret, bobPublicKey, alicePrivateKey, rand.Reader))

	require.Equal(t, aliceSharedSecret, bobSharedSecret)
}
