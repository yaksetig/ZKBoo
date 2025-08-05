package zkboo

import (
	"bytes"
	"crypto/sha1"
	"testing"
)

func TestSHA1Proof(t *testing.T) {
	msg := []byte("hello world")
	proof := ProveSHA1(msg)
	ok, reconstructed := verifySHA1(msg, proof)
	if !ok {
		t.Fatalf("verifySHA1 returned false")
	}
	expected := sha1.Sum(msg)
	if !bytes.Equal(reconstructed[:], expected[:]) {
		t.Fatalf("reconstructed hash %x does not match expected %x", reconstructed, expected)
	}
}
