package kyber

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/stretchr/testify/require"
)

func TestKyber1024(t *testing.T) {
	// Alice generates a public private key pair.
	// Alice sends her public key to Bob over an authenticated channel.
	alicePubKey, alicePrivKey, err := kyber1024.GenerateKeyPair(rand.Reader)
	require.NoError(t, err)

	// Bob then computes a sharedSecret which is contained in the ciphertext
	// which he then sends to Alice.
	ciphertext := make([]byte, kyber1024.CiphertextSize)
	sharedSecret := make([]byte, kyber1024.SharedKeySize)
	seed := make([]byte, kyber1024.EncapsulationSeedSize)
	_, err = rand.Read(seed)
	require.NoError(t, err)
	alicePubKey.EncapsulateTo(ciphertext, sharedSecret, seed)

	// Alice computes the shared secret from the ciphertext she receives from Bob.
	aliceSharedSecret := make([]byte, kyber1024.SharedKeySize)
	alicePrivKey.DecapsulateTo(aliceSharedSecret, ciphertext)

	require.Equal(t, aliceSharedSecret, sharedSecret)
}
