package protoprivacy

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/Boostport/protoprivacy/internal/generated/boostport/privacy/testing"
	"google.golang.org/protobuf/proto"
)

// exampleCrypter "encrypts" and "decrypts" messages by encoding it as base64 rather than really encrypting it.
// This is only for demonstration purposes and MUST NOT be used in production.
type exampleCrypter struct {
	deletedKeys map[string]struct{}
}

func (c *exampleCrypter) Encrypt(_ context.Context, _ string, cleartext []byte) ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(cleartext)))
	base64.StdEncoding.Encode(dst, cleartext)
	return dst, nil
}
func (c *exampleCrypter) Decrypt(_ context.Context, dataSubjectID string, ciphertext []byte) ([]byte, error) {
	if _, ok := c.deletedKeys[dataSubjectID]; ok {
		return nil, PersonalDataDeleted
	}

	dst := make([]byte, base64.StdEncoding.DecodedLen(len(ciphertext)))
	n, err := base64.StdEncoding.Decode(dst, ciphertext)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func (c *exampleCrypter) DeleteKey(dataSubjectID string) {
	c.deletedKeys[dataSubjectID] = struct{}{}
}

func Example() {
	c := &exampleCrypter{deletedKeys: make(map[string]struct{})}

	p := New(c)

	msg := testing.TestMessage_builder{
		Id:    proto.String("1234567890"),
		Data1: proto.String("test"),
		Data5: []*testing.TestNested1{
			testing.TestNested1_builder{
				Data1: proto.String("test1"),
				Data2: proto.String("test2"),
				Data3: proto.String("test3"),
				Data4: proto.String("test4"),
			}.Build(),
			testing.TestNested1_builder{
				Data1: proto.String("test5"),
				Data2: proto.String("test6"),
				Data3: proto.String("test7"),
				Data4: proto.String("test8"),
			}.Build(),
		},
	}.Build()

	encrypted, err := p.Encrypt(context.Background(), msg)
	if err != nil {
		panic(err)
	}

	fmt.Println(encrypted)

	decrypted, err := p.Decrypt(context.Background(), encrypted)
	if err != nil {
		panic(err)
	}

	fmt.Println(decrypted)

	c.DeleteKey("1234567890")

	decrypted, err = p.Decrypt(context.Background(), encrypted)
	if err != nil {
		panic(err)
	}

	fmt.Println(decrypted)
}
