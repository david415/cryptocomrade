package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/katzenpost/noise"
)

const (
	macLen    = 16
	maxMsgLen = 65535
	msg2Len   = 1680
	//msg2Len = 96
)

func main() {
	clientStaticKeypair, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}
	cs := noise.NewCipherSuiteHFS(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b, noise.HFSKyber)
	//cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cs,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeXXhfs,
		//Pattern:       noise.HandshakeXX,
		Initiator:     true,
		StaticKeypair: clientStaticKeypair,
	})

	conn, err := net.Dial("tcp", "127.0.0.1:36669")
	if err != nil {
		panic(err)
	}

	// -> e, e1
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("msg1 len is %d\n", len(msg1))
	_, err = conn.Write(msg1)
	if err != nil {
		panic(err)
	}

	// <- e, ee, ekem1, s, es
	msg2 := make([]byte, msg2Len)
	_, err = io.ReadFull(conn, msg2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("msg2 len is %d\n", len(msg2))
	_, _, _, err = hs.ReadMessage(nil, msg2)
	if err != nil {
		panic(err)
	}

	// -> s, se
	msg3, tx, rx, err := hs.WriteMessage(nil, nil)
	fmt.Printf("msg3 len is %d\n", len(msg3))
	_, err = conn.Write(msg3)
	if err != nil {
		panic(err)
	}

	// send message
	plaintext := []byte("hello Alice\n")
	ctLen := macLen + len(plaintext)
	fmt.Printf("ctLen is %d\n", ctLen)
	var ctHdr [4]byte
	binary.BigEndian.PutUint32(ctHdr[:], uint32(ctLen))
	toSend := make([]byte, 0, macLen+4+ctLen)
	toSend = tx.Encrypt(toSend, nil, ctHdr[:])
	toSend = tx.Encrypt(toSend, nil, plaintext)
	_, err = conn.Write(toSend)
	if err != nil {
		panic(err)
	}

	// receive echoed message
	var ctHdrCt [macLen + 4]byte
	_, err = io.ReadFull(conn, ctHdrCt[:])
	if err != nil {
		panic(err)
	}
	ctHdr2, err := rx.Decrypt(nil, nil, ctHdrCt[:])
	if err != nil {
		panic(err)
	}
	ctLen2 := binary.BigEndian.Uint32(ctHdr2[:])
	if ctLen2 < macLen || ctLen2 > maxMsgLen {
		panic("wtf")
	}
	fmt.Printf("ctLen2 is %d\n", ctLen2)
	ct := make([]byte, ctLen2)
	_, err = io.ReadFull(conn, ct)
	if err != nil {
		panic(err)
	}
	plaintext2, err := rx.Decrypt(nil, nil, ct)
	if err != nil {
		panic(err)
	}

	fmt.Printf("received message: %s\n", plaintext2)
}
