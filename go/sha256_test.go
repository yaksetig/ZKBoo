package zkboo

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestSHA256Proof(t *testing.T) {
	msg := []byte("hello world")
	proof := ProveSHA256(msg)
	ok, reconstructed := verifySHA256(msg, proof)
	if !ok {
		t.Fatalf("verifySHA256 returned false")
	}
	expected := sha256.Sum256(msg)
	if !bytes.Equal(reconstructed[:], expected[:]) {
		t.Fatalf("reconstructed hash %x does not match expected %x", reconstructed, expected)
	}
}
