package csidh

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/dh/sidh"
	"github.com/stretchr/testify/require"
)

func TestSIDH(t *testing.T) {

	// Allice's key pair
	prvA := sidh.NewPrivateKey(sidh.Fp503, sidh.KeyVariantSidhA)
	pubA := sidh.NewPublicKey(sidh.Fp503, sidh.KeyVariantSidhA)
	// Bob's key pair
	prvB := sidh.NewPrivateKey(sidh.Fp503, sidh.KeyVariantSidhB)
	pubB := sidh.NewPublicKey(sidh.Fp503, sidh.KeyVariantSidhB)
	// Generate keypair for Allice
	err := prvA.Generate(rand.Reader)
	require.NoError(t, err)
	prvA.GeneratePublicKey(pubA)
	// Generate keypair for Bob
	prvB.Generate(rand.Reader)
	prvB.GeneratePublicKey(pubB)
	// Buffers storing shared secret
	ssA := make([]byte, prvA.SharedSecretSize())
	ssB := make([]byte, prvA.SharedSecretSize())
	// Allice calculates shared secret with hers private
	// key and Bob's public key
	prvA.DeriveSecret(ssA[:], pubB)
	// Bob calculates shared secret with hers private
	// key and Allice's public key
	prvB.DeriveSecret(ssB[:], pubA)
	// Check if ssA == ssB
	fmt.Printf("%t\n", bytes.Equal(ssA, ssB))
}
