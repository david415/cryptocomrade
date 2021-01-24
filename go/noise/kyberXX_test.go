package noise

import (
	"crypto/rand"
	"testing"

	"github.com/katzenpost/noise"
	"github.com/stretchr/testify/require"
)

func TestNoiseKyberXX(t *testing.T) {

	clientStaticKeypair, err := noise.DH25519.GenerateKeypair(rand.Reader)
	require.NoError(t, err)

	serverStaticKeypair, err := noise.DH25519.GenerateKeypair(rand.Reader)
	require.NoError(t, err)

	cs := noise.NewCipherSuiteHFS(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b, noise.HFSKyber)

	client, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeXXhfs,
		Initiator:     true,
		StaticKeypair: clientStaticKeypair,
	})

	server, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeXXhfs,
		Initiator:     false,
		StaticKeypair: serverStaticKeypair,
	})

	// -> e, e1
	msg, _, _, err := client.WriteMessage(nil, []byte("abc"))
	require.NoError(t, err)
	t.Logf("msg 1 len is %d", len(msg))
	res, _, _, err := server.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, string(res), "abc")

	// <- e, ee, ekem1, s, es
	msg, _, _, err = server.WriteMessage(nil, []byte("defg"))
	require.NoError(t, err)
	t.Logf("msg 2 len is %d", len(msg))
	res, _, _, err = client.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, string(res), "defg")

	// -> s, se
	msg, clientTx, clientRx, err := client.WriteMessage(nil, []byte("xyz"))
	require.NoError(t, err)
	t.Logf("msg 3 len is %d", len(msg))
	res, serverRx, serverTx, err := server.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, string(res), "xyz")

	msg = clientTx.Encrypt(nil, nil, []byte("aleph"))
	res, err = serverRx.Decrypt(nil, nil, msg)
	require.NoError(t, err)
	require.Equal(t, string(res), "aleph")

	msg = serverTx.Encrypt(nil, nil, []byte("wubba"))
	res, err = clientRx.Decrypt(nil, nil, msg)
	require.NoError(t, err)
	require.Equal(t, string(res), "wubba")
}
