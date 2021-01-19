package cryptocomrade

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
)

const (
	// MACSize represents the size of a 16 byte MAC.
	MACSize = 16

	// KeySize represents the size of a 32 byte key.
	KeySize = 32
)

var (
	errKeySize  = errors.New("invalid key size")
	errSaltSize = errors.New("invalid salt size")
)

// SimplexHash is the simplest usage of a hash function
// and is suitable if you only have one use case.
func SimplexHash(data []byte) []byte {
	out := blake2b.Sum256(data)
	return out[:]
}

// Hash hashes the data with contextInfo used as the key
// for blake2's keying mechanism. contextInfo is meant to
// be a human readable string that ensures each use case of
// the hash function will have different outputs.
func Hash(contextInfo string, data []byte) ([]byte, error) {
	if len(contextInfo) > blake2b.Size {
		return nil, errors.New("contextInfo size error")
	}
	h, err := blake2b.New256([]byte(contextInfo))
	if err != nil {
		return nil, err
	}
	_, err = h.Write(data)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func kdfPairing(salt, info []byte) ([]byte, error) {
	if len(salt)+len(info) > KeySize-8 {
		return nil, errSaltSize
	}
	saltLen := make([]byte, 4)
	binary.BigEndian.PutUint32(saltLen, uint32(len(salt)))
	infoLen := make([]byte, 4)
	binary.BigEndian.PutUint32(infoLen, uint32(len(info)))
	out := []byte{}
	out = append(saltLen, infoLen...)
	out = append(out, salt...)
	out = append(out, info...)
	return out, nil
}

// Blake2bKDF is a key derivation function. It's suitable to be used with keys
// with uniform entropy and not for use with passwords/passphrases.
// salt and info are optional and must be less than 64 bytes in total.
// NOTE: I SUGGEST NOT USING THIS - instead use HKDF-SHA256.
func Blake2bKDF(key []byte, size uint32, salt, info []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errKeySize
	}
	ikm, err := kdfPairing(salt, info)
	if err != nil {
		return nil, err
	}
	xof, err := blake2b.NewXOF(size, ikm)
	if err != nil {
		return nil, err
	}
	_, err = xof.Write(key)
	if err != nil {
		return nil, err
	}
	output := make([]byte, size)
	_, err = xof.Read(output)
	if err != nil {
		return nil, err
	}
	return output, nil
}

// KDF returns a slice of derive keysNum number of derived keys of size keySize.
// The given secret must be a uniform entropy secret (ie not a password) and
// info is an optional non-secret which may be omitted.
//
// Note: in practice you probably don't want to use this particular function
// but instead use the HKDF directly where you need it.
func KDF(secret, salt, info []byte, keysNum, keySize int) ([][]byte, error) {
	hash := sha256.New
	if len(salt) != hash().Size() {
		return nil, errors.New("wrong salt size")
	}
	hkdf := hkdf.New(hash, secret, salt, info)
	var keys [][]byte
	for i := 0; i < keysNum; i++ {
		key := make([]byte, keySize)
		if _, err := io.ReadFull(hkdf, key); err != nil {
			panic(err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// HashPassword returns a 32 byte cryptographic key given
// a password and an entropic salt.
func HashPassword(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// Blake2bMAC is a MAC that uses Blake2b's keyed hash mechanism
// instead of an HMAC construction. The output is of size MACSize.
func Blake2bMAC(key, data []byte) []byte {
	h, err := blake2b.New(MACSize, key)
	if err != nil {
		panic(err)
	}
	h.Write(data)
	return h.Sum(nil)
}

// ValidBlake2bMAC reports whether Blake2b messageMAC is a valid MAC tag for message.
func ValidBlake2bMAC(message, messageMAC, key []byte) bool {
	return hmac.Equal(messageMAC, Blake2bMAC(key, message))
}

// HMACSHA256 returns the HMAC-SHA256 authentication code for the given message and key.
func HMACSHA256(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// ValidMAC reports whether messageMAC is a valid HMAC tag for message.
func ValidHMACSHA256(message, messageMAC, key []byte) bool {
	return hmac.Equal(messageMAC, HMACSHA256(message, key))
}
