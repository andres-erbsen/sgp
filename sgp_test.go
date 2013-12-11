package sgp

import "testing"
import "crypto/rand"
import "time"

const d = time.Hour
const tag = SIGN_TAG_LOCALTESING
const tag2 = SIGN_TAG_LOCALTESING2

func TestGenerateKey(t *testing.T) {
	tt := time.Now()
	pk, sk, err := GenerateKey(rand.Reader, tt, d)
	if err != nil {
		t.Error(err)
	}
	if len(pk.PublicKeys) != 2 {
		t.Errorf("Expected 2 public keys key but got %d", len(pk.PublicKeys))
	}
	_, sk2, err := GenerateKey(rand.Reader, tt, d)
	if *sk.enc == *sk2.enc {
		t.Errorf("Same secret decryption key twice")
	}
	if *sk.sign == *sk2.sign {
		t.Errorf("Same secret signature signing key twice")
	}
}

func TestSign(t *testing.T) {
	tt := time.Now()
	pk, sk, err := GenerateKey(rand.Reader, tt, d)
	if err != nil {
		t.Error(err)
	}
	msg := []byte("I will sign this message.")
	if ! pk.VerifyPb(sk.SignPb(msg,tag),tag) {
		t.Error("Signature verification failed")
	}
	if ! pk.VerifyPb(sk.SignPb(msg,tag),tag) {
		t.Error("Serialized signature verification failed")
	}
	if ! sk.Entity.VerifyPb(sk.SignPb(msg,tag),tag) {
		t.Error("Signature verification failed")
	}
}

func TestForge(t *testing.T) {
	tt := time.Now()
	pk, sk, err := GenerateKey(rand.Reader, tt, d)
	if err != nil {
		t.Error(err)
	}
	msg := []byte("I will not sign this message.")
	signed := sk.SignPb(msg,tag)
	signed.Message = []byte("I will sign this message.")
	if pk.VerifyPb(signed, tag) {
		t.Error("Forged signature passed verification")
	}
}

func TestForgeTag(t *testing.T) {
	tt := time.Now()
	pk, sk, err := GenerateKey(rand.Reader, tt, d)
	if err != nil {
		t.Error(err)
	}
	msg := []byte("I will sign this under tag 'tag'")
	if pk.VerifyPb(sk.SignPb(msg,tag),tag2) {
		t.Error("Tag-forged signature passed verification")
	}
}

func TestSerializeParseAnsSign(t *testing.T) {
	tt := time.Now()
	pk, sk, err := GenerateKey(rand.Reader, tt, d)
	if err != nil {
		t.Error(err)
	}
	pk2 := &Entity{}
	sk2 := &SecretKey{}
	sk2.Parse(sk.Serialize())
	pk2.Parse(pk.Bytes)

	msg := []byte("I will not sign this message.")
	if ! pk2.VerifyPb(sk.SignPb(msg,tag),tag) {
		t.Error("pk2.VerifyPb(sk.SignPb(msg,tag),tag) failed")
	}
	if ! pk.VerifyPb(sk2.SignPb(msg,tag),tag) {
		t.Error("pk.VerifyPb(sk2.SignPb(msg,tag),tag) failed")
	}
	if ! sk2.Entity.VerifyPb(sk2.SignPb(msg,tag),tag) {
		t.Error("sk2.Entity.VerifyPb(sk2.SignPb(msg,tag),tag) failed")
	}
	if ! sk.Entity.VerifyPb(sk2.SignPb(msg,tag),tag) {
		t.Error("sk.Entity.VerifyPb(sk2.SignPb(msg,tag),tag) failed")
	}
}
