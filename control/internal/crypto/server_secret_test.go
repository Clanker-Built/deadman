package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestWrapUnwrapServerSecret_Roundtrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	in := []byte("s3cret p@ssw0rd with unicode: ☂")
	blob, err := WrapServerSecret(&priv.PublicKey, in)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	out, err := UnwrapServerSecret(priv, blob)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(in, out) {
		t.Fatalf("plaintext mismatch: got %q want %q", out, in)
	}
}

func TestUnwrapServerSecret_Tampered(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := WrapServerSecret(&priv.PublicKey, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 0x01
	if _, err := UnwrapServerSecret(priv, blob); err == nil {
		t.Fatal("expected auth failure on tampered blob")
	}
}

func TestUnwrapServerSecret_WrongKey(t *testing.T) {
	a, _ := rsa.GenerateKey(rand.Reader, 2048)
	b, _ := rsa.GenerateKey(rand.Reader, 2048)
	blob, err := WrapServerSecret(&a.PublicKey, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapServerSecret(b, blob); err == nil {
		t.Fatal("expected failure with wrong key")
	}
}

func TestUnwrapServerSecret_Empty(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := UnwrapServerSecret(priv, []byte{}); err == nil {
		t.Fatal("expected error on empty input")
	}
	if _, err := UnwrapServerSecret(priv, []byte{0x02, 0, 0, 0}); err == nil {
		t.Fatal("expected error on bad version")
	}
}
