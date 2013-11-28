package sgp

import (
	"code.google.com/p/go.crypto/nacl/box"
	"code.google.com/p/go.crypto/sha3"
	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/ed25519"
	"io"
	"io/ioutil"
	"time"
	"errors"
)

type EncKey struct {
	Algo        PkEncAlgo
	Fingerprint []byte
	Key         interface{}
}

func (k *EncKey) Parse(algo PkEncAlgo, bytes []byte) (error) {
	switch {
	case algo == PkEncAlgo_NACL:
		if len(bytes) != 32 {
			return errors.New("PkEncAlgo_NACL public key must be 32 bytes")
		}
		h := sha3.NewKeccak512()
		h.Write(bytes)
		k.Fingerprint = h.Sum(nil)[:]

		pk := new([32]byte)
		copy(pk[:32],bytes)
		k.Key = pk
	default:
		return errors.New("Unknown public-key encryption algorithm")
	}
	k.Algo = algo
	return nil
}

type SigKey struct {
	Algo        SigAlgo
	Fingerprint []byte
	Key         interface{}
}

func (k *SigKey) Parse(algo SigAlgo, bytes []byte) (error) {
	switch {
	case algo == SigAlgo_ED25519:
		if len(bytes) != 32 {
			return errors.New("Ed25519 public key must be 32 bytes")
		}
		h := sha3.NewKeccak512()
		h.Write(bytes)
		k.Fingerprint = h.Sum(nil)[:]

		pk := new([32]byte)
		copy(pk[:32],bytes)
		k.Key = pk
	default:
		return errors.New("Unknown signature algorithm")
	}
	k.Algo = algo
	return nil
}

func (k *SigKey) Verify(message, signature []byte) bool {
	switch {
	case k.Algo == SigAlgo_ED25519:
		if len(signature) != 64 {
			return false
		}
		sig := &[64]byte{}
		copy(sig[:64],signature)
		return ed25519.Verify(k.Key.(*[32]byte), message, sig)
	default:
		return false
	}
}

type Entity struct {
	SigKeys      []*SigKey
	EncKeys      []*EncKey
	CreationTime time.Time
	Bytes        []byte
}

type SecretKey struct {
	sign *[ed25519.PrivateKeySize]byte
	enc  *[32]byte
	Entity *Entity
}

func (sk *SecretKey) SignPb(bytes []byte) *Signed {
	if len(sk.Entity.SigKeys) != 1 {
		panic("Inconsistent secret key")
	}
	return &Signed{
		Message:   bytes,
		SigAlgos:  []SigAlgo{SigAlgo_ED25519},
		SigKeyids: [][]byte{sk.Entity.SigKeys[0].Fingerprint},
		Sigs:      [][]byte{ed25519.Sign(sk.sign, bytes)[:]},
	}
}

func (sk *SecretKey) Sign(bytes []byte) []byte {
	signed := sk.SignPb(bytes)
	signed_bytes, err := proto.Marshal(signed)
	if err != nil {
		panic(err)
	}
	return signed_bytes
}

func (sk *SecretKey) Serialize() []byte {
	return append(append(sk.sign[:], sk.enc[:]...), sk.Entity.Bytes...)
}

func (sk *SecretKey) Parse(sk_bytes []byte) (err error) {
	if len(sk_bytes) < ed25519.PrivateKeySize+32 {
		return errors.New("Secret key bytes too short")
	}
	sk.Entity = &Entity{}
	err = sk.Entity.Parse(sk_bytes[ed25519.PrivateKeySize+32:])
	if err != nil {
		return
	}
	sk.sign = &[ed25519.PrivateKeySize]byte{}
	sk.enc = &[32]byte{}
	copy(sk.sign[:], sk_bytes[:ed25519.PrivateKeySize])
	copy(sk.enc[:], sk_bytes[ed25519.PrivateKeySize:ed25519.PrivateKeySize+32])
	err = nil
	return
}

func LoadSecretKeyFromFile(filename string) (sk SecretKey, err error) {
	sk_bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	err = sk.Parse(sk_bytes)
	return
}


func GenerateKey(rand io.Reader, now time.Time) (e *Entity, sk SecretKey, err error) {
	var pk_sign, pk_enc *[32]byte
	pk_sign, sk.sign, err = ed25519.GenerateKey(rand)
	if err != nil {
		return
	}

	pk_enc, sk.enc, err = box.GenerateKey(rand)
	if err != nil {
		return
	}

	// Self-sign the key
	t := new(int64)
	*t = now.Unix()
	pkd := &PublicKeyData{
		SigAlgos: []SigAlgo{SigAlgo_ED25519},
		EncAlgos: []PkEncAlgo{PkEncAlgo_NACL},
		SigKeys:  [][]byte{pk_sign[:]},
		EncKeys:  [][]byte{pk_enc[:]},
		Time:     t,
	}
	pkd_bytes, err := proto.Marshal(pkd)
	if err != nil {
		return
	}
	e_msg := &Signed{
		Message:   pkd_bytes,
		SigAlgos:  []SigAlgo{SigAlgo_ED25519},
		Sigs:      [][]byte{ed25519.Sign(sk.sign, pkd_bytes)[:]},
	}

	e_bytes, err := proto.Marshal(e_msg)
	if err != nil {
		return
	}
	sk.Entity = new(Entity)
	e = sk.Entity
	err = e.Parse(e_bytes)
	return
}

func (e *Entity) Parse(e_bytes []byte) (err error) {
	e_msg := &Signed{}
	err = proto.Unmarshal(e_bytes, e_msg)
	if err != nil {
		return
	}
	pkd := &PublicKeyData{}
	err = proto.Unmarshal(e_msg.Message, pkd)
	if err != nil {
		return
	}

	if  len(pkd.EncKeys) != len(pkd.EncAlgos) {
		err = errors.New("PublicKeyData needs exactly one enc key per enc algo")
	}
	if  len(pkd.SigKeys) != len(pkd.SigAlgos) {
		err = errors.New("PublicKeyData needs exactly one sig key per sig algo")
	}
	if  len(pkd.SigKeys) != len(e_msg.Sigs) {
		err = errors.New("PublicKey needs exactly one signature per sig key")
	}

	for i:=0; i<len(pkd.SigAlgos); i++ {
		k := new(SigKey)
		k.Parse(pkd.SigAlgos[i], pkd.SigKeys[i])
		if k.Verify(e_msg.Message, e_msg.Sigs[i]) {
			e.SigKeys = append(e.SigKeys, k)
		}
	}
	if len(e.SigKeys) == 0 {
		return errors.New("No useable signing keys found")
	}

	for i:=0; i<len(pkd.EncAlgos); i++ {
		k := new(EncKey)
		k.Parse(pkd.EncAlgos[i], pkd.EncKeys[i])
		e.EncKeys = append(e.EncKeys, k)
	}

	if pkd.Time != nil {
		e.CreationTime = time.Unix(*pkd.Time, 0)
	}

	e.Bytes = e_bytes
	return
}

func (e *Entity) VerifyPb(sigmsg *Signed) bool {
	if len(sigmsg.SigKeyids) == 0 || len(sigmsg.SigKeyids) != len(sigmsg.Sigs) {
		return false
	}
	if len(sigmsg.SigAlgos ) != len(sigmsg.Sigs) {
		return false
	}
	for sig_index, signerid := range sigmsg.SigKeyids {
		for _, pk := range e.SigKeys {
			if sigmsg.SigAlgos[sig_index] != pk.Algo {
				continue
			}
			equal := true
			for i:=0; i<len(signerid) && i< len(pk.Fingerprint); i++ {
				if signerid[i] != pk.Fingerprint[i] {
					equal = false
					break
				}
			}
			if equal {
				return pk.Verify(sigmsg.Message, sigmsg.Sigs[sig_index])
			}
		}
	}
	return false
}

func (e *Entity) Verify(signed_bytes []byte) ([]byte, error) {
	errfailed := errors.New("Signature verification failed")
	signed:= &Signed{}
	err := proto.Unmarshal(signed_bytes, signed)
	if err != nil {
		return []byte{}, errfailed
	}
	ok := e.VerifyPb(signed)
	if ok {
		return signed.Message, nil
	} else {
		return []byte{}, errfailed
	}
}
