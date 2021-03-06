// Code generated by protoc-gen-go.
// source: sgp.proto
// DO NOT EDIT!

package sgp

import proto "code.google.com/p/goprotobuf/proto"
import json "encoding/json"
import math "math"

// Reference proto, json, and math imports to suppress error if they are not otherwise used.
var _ = proto.Marshal
var _ = &json.SyntaxError{}
var _ = math.Inf

type PublickeyAlgorithm int32

const (
	PublickeyAlgorithm_CURVE25519 PublickeyAlgorithm = 1
	PublickeyAlgorithm_ED25519    PublickeyAlgorithm = 2
)

var PublickeyAlgorithm_name = map[int32]string{
	1: "CURVE25519",
	2: "ED25519",
}
var PublickeyAlgorithm_value = map[string]int32{
	"CURVE25519": 1,
	"ED25519":    2,
}

func (x PublickeyAlgorithm) Enum() *PublickeyAlgorithm {
	p := new(PublickeyAlgorithm)
	*p = x
	return p
}
func (x PublickeyAlgorithm) String() string {
	return proto.EnumName(PublickeyAlgorithm_name, int32(x))
}
func (x PublickeyAlgorithm) MarshalJSON() ([]byte, error) {
	return json.Marshal(x.String())
}
func (x *PublickeyAlgorithm) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(PublickeyAlgorithm_value, data, "PublickeyAlgorithm")
	if err != nil {
		return err
	}
	*x = PublickeyAlgorithm(value)
	return nil
}

type Signed struct {
	Message          []byte   `protobuf:"bytes,1,req,name=message" json:"message,omitempty"`
	KeyIds           [][]byte `protobuf:"bytes,3,rep,name=key_ids" json:"key_ids,omitempty"`
	Sigs             [][]byte `protobuf:"bytes,4,rep,name=sigs" json:"sigs,omitempty"`
	XXX_unrecognized []byte   `json:"-"`
}

func (m *Signed) Reset()         { *m = Signed{} }
func (m *Signed) String() string { return proto.CompactTextString(m) }
func (*Signed) ProtoMessage()    {}

func (m *Signed) GetMessage() []byte {
	if m != nil {
		return m.Message
	}
	return nil
}

func (m *Signed) GetKeyIds() [][]byte {
	if m != nil {
		return m.KeyIds
	}
	return nil
}

func (m *Signed) GetSigs() [][]byte {
	if m != nil {
		return m.Sigs
	}
	return nil
}

type PublicKey struct {
	Usage                   *uint32             `protobuf:"varint,1,req,name=usage" json:"usage,omitempty"`
	AuthorizedSignatureTags []uint64            `protobuf:"varint,2,rep,name=authorized_signature_tags" json:"authorized_signature_tags,omitempty"`
	Algo                    *PublickeyAlgorithm `protobuf:"varint,3,req,name=algo,enum=PublickeyAlgorithm" json:"algo,omitempty"`
	Key                     []byte              `protobuf:"bytes,4,req,name=key" json:"key,omitempty"`
	Fingerprint             []byte              `protobuf:"bytes,5,opt,name=fingerprint" json:"fingerprint,omitempty"`
	XXX_unrecognized        []byte              `json:"-"`
}

func (m *PublicKey) Reset()         { *m = PublicKey{} }
func (m *PublicKey) String() string { return proto.CompactTextString(m) }
func (*PublicKey) ProtoMessage()    {}

func (m *PublicKey) GetUsage() uint32 {
	if m != nil && m.Usage != nil {
		return *m.Usage
	}
	return 0
}

func (m *PublicKey) GetAuthorizedSignatureTags() []uint64 {
	if m != nil {
		return m.AuthorizedSignatureTags
	}
	return nil
}

func (m *PublicKey) GetAlgo() PublickeyAlgorithm {
	if m != nil && m.Algo != nil {
		return *m.Algo
	}
	return 0
}

func (m *PublicKey) GetKey() []byte {
	if m != nil {
		return m.Key
	}
	return nil
}

func (m *PublicKey) GetFingerprint() []byte {
	if m != nil {
		return m.Fingerprint
	}
	return nil
}

type EntityData struct {
	PublicKeys       []*PublicKey `protobuf:"bytes,1,rep,name=public_keys" json:"public_keys,omitempty"`
	Time             *int64       `protobuf:"varint,2,opt,name=time" json:"time,omitempty"`
	Lifetime         *int64       `protobuf:"varint,3,opt,name=lifetime" json:"lifetime,omitempty"`
	XXX_unrecognized []byte       `json:"-"`
}

func (m *EntityData) Reset()         { *m = EntityData{} }
func (m *EntityData) String() string { return proto.CompactTextString(m) }
func (*EntityData) ProtoMessage()    {}

func (m *EntityData) GetPublicKeys() []*PublicKey {
	if m != nil {
		return m.PublicKeys
	}
	return nil
}

func (m *EntityData) GetTime() int64 {
	if m != nil && m.Time != nil {
		return *m.Time
	}
	return 0
}

func (m *EntityData) GetLifetime() int64 {
	if m != nil && m.Lifetime != nil {
		return *m.Lifetime
	}
	return 0
}

func init() {
	proto.RegisterEnum("PublickeyAlgorithm", PublickeyAlgorithm_name, PublickeyAlgorithm_value)
}
