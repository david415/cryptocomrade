package hash

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHash(t *testing.T) {
	data1 := []byte("The Cypherpunks are actively engaged in making the networks safer for privacy.")
	hash1, err := Hash("ciphertext", data1)
	require.NoError(t, err)
	hash2, err := Hash("plaintext", data1)
	require.NoError(t, err)
	require.NotEqual(t, hash1, hash2)
}

func TestBlake2bKDF(t *testing.T) {
	key := make([]byte, KeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)

	biggerKey1, err := Blake2bKDF(key, 512, nil, nil)
	require.NoError(t, err)

	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	biggerKey2, err := Blake2bKDF(key, 512, salt, nil)
	require.NoError(t, err)
	require.NotEqual(t, biggerKey1, biggerKey2)

	info := []byte{10, 9, 8, 7}
	biggerKey3, err := Blake2bKDF(key, 512, nil, info)
	require.NoError(t, err)
	require.NotEqual(t, biggerKey1, biggerKey3)
	require.NotEqual(t, biggerKey2, biggerKey3)

	biggerKey4, err := Blake2bKDF(key, 512, salt, info)
	require.NoError(t, err)
	biggerKey5, err := Blake2bKDF(key, 512, append(salt, info...), nil)
	require.NoError(t, err)
	require.NotEqual(t, biggerKey4, biggerKey5)
	biggerKey6, err := Blake2bKDF(key, 512, nil, append(salt, info...))
	require.NoError(t, err)
	require.NotEqual(t, biggerKey6, biggerKey5)
	require.NotEqual(t, biggerKey6, biggerKey4)
}

func TestHashPassword(t *testing.T) {
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8} // use a more entropic salt than this
	password := []byte("my silly passphrase")
	key := HashPassword(password, salt)
	t.Logf("key: %x", key)
}

func TestValidBlake2bMAC(t *testing.T) {
	data := []byte("We must defend our own privacy if we expect to have any.")

	key1 := make([]byte, KeySize)
	_, err := rand.Read(key1)
	require.NoError(t, err)

	mac1 := Blake2bMAC(key1, data)
	require.True(t, ValidBlake2bMAC(data, mac1, key1))

	key2 := make([]byte, KeySize)
	_, err = rand.Read(key2)
	require.NoError(t, err)

	mac2 := Blake2bMAC(key2, data)
	require.NotEqual(t, mac1, mac2)

	require.True(t, ValidBlake2bMAC(data, mac2, key2))
	require.False(t, ValidBlake2bMAC(data, mac2, key1))
}
