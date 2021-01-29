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

	alicePrivateKeyBytes := make([]byte, csidh.PrivateKeySize)
	require.True(t, alicePrivateKey.Export(alicePrivateKeyBytes))
	t.Logf("Alice's private key: %x", alicePrivateKeyBytes)

	alicePublicKey := new(csidh.PublicKey)
	csidh.GeneratePublicKey(alicePublicKey, alicePrivateKey, rand.Reader)
	require.True(t, csidh.Validate(alicePublicKey, rand.Reader))

	alicePublicKeyBytes := make([]byte, csidh.PublicKeySize)
	require.True(t, alicePublicKey.Export(alicePublicKeyBytes))
	t.Logf("Alice's public key: %x", alicePublicKeyBytes)

	// Bob
	bobPrivateKey := new(csidh.PrivateKey)
	err = csidh.GeneratePrivateKey(bobPrivateKey, rand.Reader)
	require.NoError(t, err)

	bobPrivateKeyBytes := make([]byte, csidh.PrivateKeySize)
	require.True(t, bobPrivateKey.Export(bobPrivateKeyBytes))
	t.Logf("Bob's private key: %x", bobPrivateKeyBytes)

	bobPublicKey := new(csidh.PublicKey)
	csidh.GeneratePublicKey(bobPublicKey, bobPrivateKey, rand.Reader)
	require.True(t, csidh.Validate(bobPublicKey, rand.Reader))

	bobPublicKeyBytes := make([]byte, csidh.PublicKeySize)
	require.True(t, bobPublicKey.Export(bobPublicKeyBytes))
	t.Logf("Bob's public key: %x", bobPublicKeyBytes)

	// Alice sends her public key to Bob over an authenticated channel
	// and Bob computes their shared secret:
	bobSharedSecret := [csidh.SharedSecretSize]byte{}
	require.True(t, csidh.DeriveSecret(&bobSharedSecret, alicePublicKey, bobPrivateKey, rand.Reader))

	// Bob sends his public key to Alice over an authenticated channel
	// and Alice computes their shared secret:
	aliceSharedSecret := [csidh.SharedSecretSize]byte{}
	require.True(t, csidh.DeriveSecret(&aliceSharedSecret, bobPublicKey, alicePrivateKey, rand.Reader))

	require.Equal(t, aliceSharedSecret, bobSharedSecret)
	t.Logf("Shared secret: %x", aliceSharedSecret[:])
}
