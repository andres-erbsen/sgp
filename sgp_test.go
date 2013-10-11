package sgp

import "testing"
import "crypto/rand"
import "time"

func TestGenerateKey(t *testing.T) {
	tt := time.Now()
	pk, sk, err := GenerateKey(rand.Reader, tt)
	if err != nil {
		t.Error(err)
	}
	if len(pk.SigKeys) != 1 {
		t.Errorf("Expected 1 signing key but got %d", len(pk.SigKeys))
	}
	if len(pk.EncKeys) != 1 {
		t.Errorf("Expected 1 encryption key but got %d", len(pk.EncKeys))
	}
	_, sk2, err := GenerateKey(rand.Reader, tt)
	if *sk.enc == *sk2.enc {
		t.Errorf("Same secret decryption key twice")
	}
	if *sk.sign == *sk2.sign {
		t.Errorf("Same secret signature signing key twice")
	}
}

func TestSign(t *testing.T) {
	tt := time.Now()
	pk, sk, err := GenerateKey(rand.Reader, tt)
	if err != nil {
		t.Error(err)
	}
	msg := []byte("I will not sign this message.")
	if ! pk.Verify(sk.Sign(msg)) {
		t.Error("Signature verification failed")
	}
}

func TestForge(t *testing.T) {
	tt := time.Now()
	pk, sk, err := GenerateKey(rand.Reader, tt)
	if err != nil {
		t.Error(err)
	}
	msg := []byte("I will not sign this message.")
	signed := sk.Sign(msg)
	signed.Message = []byte("I will sign this message.")
	if pk.Verify(signed) {
		t.Error("Forged signature passed verification")
	}
}
