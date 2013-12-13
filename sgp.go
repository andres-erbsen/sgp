package sgp

import (
	"code.google.com/p/go.crypto/nacl/box"
	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/ed25519"
	"crypto/sha256"
	"io"
	"io/ioutil"
	"time"
	"errors"
	"bytes"
)


const (
	SIGN_TAG_WILDCARD = uint64(iota)
	SIGN_TAG_SELFSIGN
	SIGN_TAG_LOCALTESING2 = 0xfffffffffffffffe
	SIGN_TAG_LOCALTESING = 0xffffffffffffffff
)

const ( // enum PublicKey::Usage
	PublicKey_SIGNING = uint32(1<<iota)
	PublicKey_PUBLICKEY_ENCRYPTION
	PublicKey_KEY_AGREEMENT
)

const OUR_SIGKEY_INDEX = 0

var errVerifyFailed = errors.New("Signature verification failed")
var errNoPubKey = errors.New("No suitable public key available")

func (pk *PublicKey) ComputeFingerprint() []byte {
	if pk.Fingerprint == nil {
		h := sha256.New()
		h.Write(pk.Key)
		pk.Fingerprint = h.Sum(nil)[:]
	}
	return pk.Fingerprint
}

type SecretKey struct {
	sign *[ed25519.PrivateKeySize]byte
	enc  *[32]byte
	Entity *Entity
}

func (sk *SecretKey) SignPb(message []byte, tag uint64) *Signed {
	// TODO: should this check whether the public key is marked
	// as authorized to sign under this tag
	tagged_msg := append(proto.EncodeVarint(tag), message...)
	return &Signed{
		Message:   message,
		KeyIds:    [][]byte{sk.Entity.PublicKeys[OUR_SIGKEY_INDEX].ComputeFingerprint()},
		Sigs:      [][]byte{ed25519.Sign(sk.sign, tagged_msg)[:]},
	}
}

func (sk *SecretKey) Sign(message []byte, tag uint64) []byte {
	signed_bytes, err := proto.Marshal(sk.SignPb(message, tag))
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

type Entity struct {
	PublicKeys   []*PublicKey
	Fingerprints [][]byte
	CreationTime time.Time
	ExpirationTime time.Time
	Bytes        []byte
}

func GenerateKey(rand io.Reader, now time.Time, lifetime time.Duration) (e *Entity, sk SecretKey, err error) {
	var pk_sign_bs, pk_enc_bs *[32]byte
	pk_sign_bs, sk.sign, err = ed25519.GenerateKey(rand)
	if err != nil {
		return
	}
	_PublicKey_SIGNING := PublicKey_SIGNING
	_PublickeyAlgorithm_ED25519 := PublickeyAlgorithm_ED25519
	pk_sign := &PublicKey{Usage: &_PublicKey_SIGNING,
		AuthorizedSignatureTags: []uint64{SIGN_TAG_WILDCARD},
		Algo: &_PublickeyAlgorithm_ED25519,
		Key: pk_sign_bs[:]}

	pk_enc_bs, sk.enc, err = box.GenerateKey(rand)
	if err != nil {
		return
	}

	u := PublicKey_KEY_AGREEMENT | PublicKey_PUBLICKEY_ENCRYPTION
	_PublickeyAlgorithm_CURVE25519 := PublickeyAlgorithm_CURVE25519
	pk_enc := &PublicKey{Algo: &_PublickeyAlgorithm_CURVE25519,
		Usage: &u,
		Key: pk_enc_bs[:]}

	// Self-sign the key
	t := new(int64)
	*t = now.Unix()
	d := new(int64)
	*d = int64(lifetime.Seconds())
	ed := &EntityData{
		PublicKeys: []*PublicKey{pk_sign, pk_enc},
		Time:       t,
		Lifetime:   d,
	}
	ed_bytes, err := proto.Marshal(ed)
	if err != nil {
		return
	}
	tagged_msg := append(proto.EncodeVarint(SIGN_TAG_SELFSIGN), ed_bytes...)
	e_msg := &Signed{
		Message: ed_bytes,
		Sigs:    [][]byte{ed25519.Sign(sk.sign, tagged_msg)[:]}}

	e_bytes, err := proto.Marshal(e_msg)
	if err != nil {
		return
	}
	sk.Entity = new(Entity)
	e = sk.Entity
	err = e.Parse(e_bytes)
	return
}

func (pk *PublicKey) RawVerify (message, signature []byte) bool {
	switch *pk.Algo {
	case PublickeyAlgorithm_ED25519:
		pk_arr := new([ed25519.PublicKeySize]byte)
		copy(pk_arr[:], pk.Key)
		sig_arr := new([ed25519.SignatureSize]byte)
		copy(sig_arr[:], signature)
		return ed25519.Verify(pk_arr, message, sig_arr)
	default: return false
	}
}

func (pk *PublicKey) CanSign(tag uint64) bool {
	if *pk.Usage & PublicKey_SIGNING == 0 {
		return false
	}
	for _, allowed_tag := range pk.AuthorizedSignatureTags {
		if tag == allowed_tag || allowed_tag == SIGN_TAG_WILDCARD {
			return true
		}
	}
	return false
}

func (pk *PublicKey) verifySignature (message, signature []byte, tag uint64) bool {
	tagged_msg := append(proto.EncodeVarint(tag), message...)
	return pk.CanSign(tag) && pk.RawVerify(tagged_msg, signature)
}

func (e *Entity) Parse(e_bytes []byte) (err error) {
	e_msg := &Signed{}
	err = proto.Unmarshal(e_bytes, e_msg)
	if err != nil {
		return
	}
	ed := &EntityData{}
	err = proto.Unmarshal(e_msg.Message, ed)
	if err != nil {
		return
	}

	i := 0
	for _, pk := range ed.PublicKeys {
		pk.Fingerprint = nil // do not trust what came from the network
		if pk.CanSign(SIGN_TAG_SELFSIGN) {
			if pk.verifySignature(e_msg.Message, e_msg.Sigs[i], SIGN_TAG_SELFSIGN) {
				e.Fingerprints = append(e.Fingerprints, pk.ComputeFingerprint())
			} else {
				return errVerifyFailed
			}
		i++
		}
	}
	e.PublicKeys = ed.PublicKeys

	if ed.Time != nil {
		e.CreationTime = time.Unix(*ed.Time, 0)
		if ed.Lifetime != nil {
			e.ExpirationTime = e.CreationTime.Add(time.Duration(*ed.Lifetime) * time.Second)
		}
	}

	e.Bytes = e_bytes
	return
}

func (e *Entity) VerifyPb(sigmsg *Signed, tag uint64) bool {
	for i, signerid := range sigmsg.KeyIds {
		for _, pk := range e.PublicKeys {
			if bytes.Equal(signerid, pk.ComputeFingerprint()) &&
        	   pk.verifySignature(sigmsg.Message, sigmsg.Sigs[i], tag) {
				return true
			}
		}
	}
	return false
}

func (e *Entity) Verify(signed_bytes []byte, tag uint64) ([]byte, error) {
	signed:= &Signed{}
	err := proto.Unmarshal(signed_bytes, signed)
	if err != nil {
		return []byte{}, errVerifyFailed
	}
	ok := e.VerifyPb(signed, tag)
	if ok {
		return signed.Message, nil
	} else {
		return []byte{}, errVerifyFailed
	}
}


func (e *Entity) FirstKeyFor(usage uint32) *PublicKey {
	for _, pk := range e.PublicKeys {
		if *pk.Usage & usage != 0 {
			return pk
		}
	}
	return nil
}

func Compare(l, r *Entity) int {
	var l_pk, r_pk *PublicKey
	for _, l_pk = range l.PublicKeys {
		if l_pk.CanSign(SIGN_TAG_SELFSIGN) {
			break
		}
	}
	for _, r_pk = range r.PublicKeys {
		if r_pk.CanSign(SIGN_TAG_SELFSIGN) {
			break
		}
	}
	return bytes.Compare(l_pk.Key, r_pk.Key)
}

func (e *Entity) CanonicalKeyFor(usage uint32, r *Entity) *PublicKey {
	l := e
	if Compare(l, r) > 0 {
		l,r = r,l
	}
	
	for _, l_pk := range l.PublicKeys {
		if *l_pk.Usage & usage == 0 {
			continue
		}
		for _, r_pk := range r.PublicKeys {
			if *r_pk.Algo != *l_pk.Algo || *r_pk.Usage & usage == 0 {
				continue
			}
			if e == l {
				return r_pk
			} else {
				return l_pk
			}
		}
	}
	return nil
}

func (sk *SecretKey) CanonicalKeyAgreement(r *Entity) ([]byte, error) {
	r_pk := sk.Entity.CanonicalKeyFor(PublicKey_KEY_AGREEMENT, r)
	if r_pk == nil {
		return nil, errNoPubKey
	}
	switch *r_pk.Algo {
	case PublickeyAlgorithm_CURVE25519:
		k := new([32]byte)
		pk := new([32]byte)
		copy(pk[:], r_pk.Key)
		box.Precompute(k, pk, sk.enc)
		return (*k)[:], nil
	}
	return nil, errNoPubKey
}
