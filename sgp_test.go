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
	if ! pk.VerifyPb(sk.SignPb(msg)) {
		t.Error("Signature verification failed")
	}
	if ! pk.VerifyPb(sk.SignPb(msg)) {
		t.Error("Serialized signature verification failed")
	}
	if ! sk.Entity.VerifyPb(sk.SignPb(msg)) {
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
	signed := sk.SignPb(msg)
	signed.Message = []byte("I will sign this message.")
	if pk.VerifyPb(signed) {
		t.Error("Forged signature passed verification")
	}
}

func TestSerializeParseAnsSign(t *testing.T) {
	tt := time.Now()
	pk, sk, err := GenerateKey(rand.Reader, tt)
	if err != nil {
		t.Error(err)
	}
	pk2 := &Entity{}
	sk2 := &SecretKey{}
	sk2.Parse(sk.Serialize())
	pk2.Parse(pk.Bytes)

	msg := []byte("I will not sign this message.")
	if ! pk2.VerifyPb(sk.SignPb(msg)) {
		t.Error("pk2.VerifyPb(sk.SignPb(msg)) failed")
	}
	if ! pk.VerifyPb(sk2.SignPb(msg)) {
		t.Error("pk.VerifyPb(sk2.SignPb(msg)) failed")
	}
	if ! sk2.Entity.VerifyPb(sk2.SignPb(msg)) {
		t.Error("sk2.Entity.VerifyPb(sk2.SignPb(msg)) failed")
	}
	if ! sk.Entity.VerifyPb(sk2.SignPb(msg)) {
		t.Error("sk.Entity.VerifyPb(sk2.SignPb(msg)) failed")
	}
}
