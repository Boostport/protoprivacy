package protoprivacy

import (
	"encoding/base64"
	"testing"

	testprotos "github.com/Boostport/protoprivacy/internal/generated/boostport/privacy/testing"
	"google.golang.org/protobuf/proto"
)

// fakeCrypter "encrypts" and "decrypts" messages by encoding it as base64 rather than really encrypting it.
// This is only for testing purposes and MUST NOT be used in production.
type fakeCrypter struct{}

func (f fakeCrypter) Encrypt(dataSubjectID string, cleartext []byte) ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(cleartext)))
	base64.StdEncoding.Encode(dst, cleartext)
	return dst, nil
}
func (f fakeCrypter) Decrypt(dataSubjectID string, ciphertext []byte) ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(ciphertext)))
	n, err := base64.StdEncoding.Decode(dst, ciphertext)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

type fakeDeletedDataSubjectCrypter struct{}

func (f fakeDeletedDataSubjectCrypter) Encrypt(dataSubjectID string, cleartext []byte) ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(cleartext)))
	base64.StdEncoding.Encode(dst, cleartext)
	return dst, nil
}
func (f fakeDeletedDataSubjectCrypter) Decrypt(dataSubjectID string, ciphertext []byte) ([]byte, error) {
	return nil, PersonalDataDeleted
}

func TestPrivacyEncryptionAndDecryption(t *testing.T) {

	for _, tt := range []struct {
		explanation string
		proto       proto.Message
	}{
		{
			explanation: "Simple",
			proto: testprotos.TestMessage_builder{
				Id:    proto.String("123"),
				Data1: proto.String("test"),
			}.Build(),
		},
		{
			explanation: "Nested messages",
			proto: testprotos.TestMessage_builder{
				Id: proto.String("123"),
				Data2: testprotos.TestNested1_builder{
					Data1: proto.String("test1"),
					Data2: proto.String("test2"),
					Data3: proto.String("test3"),
					Data4: proto.String("test4"),
				}.Build(),
				Data3: testprotos.TestNested2_builder{
					Data1: proto.String("test1"),
					Data2: proto.String("test2"),
					Data3: proto.String("test3"),
					Data4: proto.String("test4"),
				}.Build(),
			}.Build(),
		},
		{
			explanation: "Repeated",
			proto: testprotos.TestMessage_builder{
				Id:    proto.String("123"),
				Data4: []string{"test1", "test2", "test3"},
				Data5: []*testprotos.TestNested1{
					testprotos.TestNested1_builder{
						Data1: proto.String("test1"),
						Data2: proto.String("test2"),
						Data3: proto.String("test3"),
						Data4: proto.String("test4"),
					}.Build(),
					testprotos.TestNested1_builder{
						Data1: proto.String("test5"),
						Data2: proto.String("test6"),
						Data3: proto.String("test7"),
						Data4: proto.String("test8"),
					}.Build(),
					testprotos.TestNested1_builder{
						Data1: proto.String("test9"),
						Data2: proto.String("test10"),
						Data3: proto.String("test11"),
						Data4: proto.String("test12"),
					}.Build(),
				},
				Data6: []*testprotos.TestNested2{
					testprotos.TestNested2_builder{
						Data1: proto.String("test1"),
						Data2: proto.String("test2"),
						Data3: proto.String("test3"),
						Data4: proto.String("test4"),
					}.Build(),
					testprotos.TestNested2_builder{
						Data1: proto.String("test5"),
						Data2: proto.String("test6"),
						Data3: proto.String("test7"),
						Data4: proto.String("test8"),
					}.Build(),
					testprotos.TestNested2_builder{
						Data1: proto.String("test9"),
						Data2: proto.String("test10"),
						Data3: proto.String("test11"),
						Data4: proto.String("test12"),
					}.Build(),
				},
			}.Build(),
		},
		{
			explanation: "Map",
			proto: testprotos.TestMessage_builder{
				Id: proto.String("123"),
				Data7: map[string]string{
					"test1": "test2",
					"test3": "test4",
					"test5": "test6",
				},
				Data8: map[string]*testprotos.TestNested1{
					"test1": testprotos.TestNested1_builder{
						Data1: proto.String("test1"),
						Data2: proto.String("test2"),
						Data3: proto.String("test3"),
						Data4: proto.String("test4"),
					}.Build(),
					"test2": testprotos.TestNested1_builder{
						Data1: proto.String("test5"),
						Data2: proto.String("test6"),
						Data3: proto.String("test7"),
						Data4: proto.String("test8"),
					}.Build(),
					"test3": testprotos.TestNested1_builder{
						Data1: proto.String("test9"),
						Data2: proto.String("test10"),
						Data3: proto.String("test11"),
						Data4: proto.String("test12"),
					}.Build(),
				},
				Data9: map[string]*testprotos.TestNested2{
					"test1": testprotos.TestNested2_builder{
						Data1: proto.String("test1"),
						Data2: proto.String("test2"),
						Data3: proto.String("test3"),
						Data4: proto.String("test4"),
					}.Build(),
					"test2": testprotos.TestNested2_builder{
						Data1: proto.String("test5"),
						Data2: proto.String("test6"),
						Data3: proto.String("test7"),
						Data4: proto.String("test8"),
					}.Build(),
					"test3": testprotos.TestNested2_builder{
						Data1: proto.String("test9"),
						Data2: proto.String("test10"),
						Data3: proto.String("test11"),
						Data4: proto.String("test12"),
					}.Build(),
				},
			}.Build(),
		},
	} {
		p := New(fakeCrypter{})

		t.Run(tt.explanation, func(t *testing.T) {
			envelope, err := p.Encrypt(tt.proto)
			if err != nil {
				t.Fatalf("Error encrypting message: %v", err)
			}

			decrypted, err := p.Decrypt(envelope)
			if err != nil {
				t.Fatalf("Error decrypting message: %v", err)
			}

			if !proto.Equal(tt.proto, decrypted) {
				t.Error("Decrypted message does not match original message")
			}
		})
	}
}

func TestPrivacyEncryptionAndDecryptionAfterDeletion(t *testing.T) {
	for _, tt := range []struct {
		explanation string
		proto       proto.Message
		expected    proto.Message
	}{
		{
			explanation: "All fields",
			proto: testprotos.TestMessage_builder{
				Id:    proto.String("123"),
				Data1: proto.String("test"),
				Data2: testprotos.TestNested1_builder{
					Data1: proto.String("test1"),
					Data2: proto.String("test2"),
					Data3: proto.String("test3"),
					Data4: proto.String("test4"),
				}.Build(),
				Data3: testprotos.TestNested2_builder{
					Data1: proto.String("test1"),
					Data2: proto.String("test2"),
					Data3: proto.String("test3"),
					Data4: proto.String("test4"),
				}.Build(),
				Data4: []string{"test1", "test2", "test3"},
				Data5: []*testprotos.TestNested1{
					testprotos.TestNested1_builder{
						Data1: proto.String("test1"),
						Data2: proto.String("test2"),
						Data3: proto.String("test3"),
						Data4: proto.String("test4"),
					}.Build(),
					testprotos.TestNested1_builder{
						Data1: proto.String("test5"),
						Data2: proto.String("test6"),
						Data3: proto.String("test7"),
						Data4: proto.String("test8"),
					}.Build(),
					testprotos.TestNested1_builder{
						Data1: proto.String("test9"),
						Data2: proto.String("test10"),
						Data3: proto.String("test11"),
						Data4: proto.String("test12"),
					}.Build(),
				},
				Data6: []*testprotos.TestNested2{
					testprotos.TestNested2_builder{
						Data1: proto.String("test1"),
						Data2: proto.String("test2"),
						Data3: proto.String("test3"),
						Data4: proto.String("test4"),
					}.Build(),
					testprotos.TestNested2_builder{
						Data1: proto.String("test5"),
						Data2: proto.String("test6"),
						Data3: proto.String("test7"),
						Data4: proto.String("test8"),
					}.Build(),
					testprotos.TestNested2_builder{
						Data1: proto.String("test9"),
						Data2: proto.String("test10"),
						Data3: proto.String("test11"),
						Data4: proto.String("test12"),
					}.Build(),
				},
				Data7: map[string]string{
					"test1": "test2",
					"test3": "test4",
					"test5": "test6",
				},
				Data8: map[string]*testprotos.TestNested1{
					"test1": testprotos.TestNested1_builder{
						Data1: proto.String("test1"),
						Data2: proto.String("test2"),
						Data3: proto.String("test3"),
						Data4: proto.String("test4"),
					}.Build(),
					"test2": testprotos.TestNested1_builder{
						Data1: proto.String("test5"),
						Data2: proto.String("test6"),
						Data3: proto.String("test7"),
						Data4: proto.String("test8"),
					}.Build(),
					"test3": testprotos.TestNested1_builder{
						Data1: proto.String("test9"),
						Data2: proto.String("test10"),
						Data3: proto.String("test11"),
						Data4: proto.String("test12"),
					}.Build(),
				},
				Data9: map[string]*testprotos.TestNested2{
					"test1": testprotos.TestNested2_builder{
						Data1: proto.String("test1"),
						Data2: proto.String("test2"),
						Data3: proto.String("test3"),
						Data4: proto.String("test4"),
					}.Build(),
					"test2": testprotos.TestNested2_builder{
						Data1: proto.String("test5"),
						Data2: proto.String("test6"),
						Data3: proto.String("test7"),
						Data4: proto.String("test8"),
					}.Build(),
					"test3": testprotos.TestNested2_builder{
						Data1: proto.String("test9"),
						Data2: proto.String("test10"),
						Data3: proto.String("test11"),
						Data4: proto.String("test12"),
					}.Build(),
				},
			}.Build(),
			expected: testprotos.TestMessage_builder{
				Id: proto.String("123"),
				Data2: testprotos.TestNested1_builder{
					Data4: proto.String("test4"),
				}.Build(),
				Data5: []*testprotos.TestNested1{
					testprotos.TestNested1_builder{
						Data4: proto.String("test4"),
					}.Build(),
					testprotos.TestNested1_builder{
						Data4: proto.String("test8"),
					}.Build(),
					testprotos.TestNested1_builder{
						Data4: proto.String("test12"),
					}.Build(),
				},
				Data8: map[string]*testprotos.TestNested1{
					"test1": testprotos.TestNested1_builder{
						Data4: proto.String("test4"),
					}.Build(),
					"test2": testprotos.TestNested1_builder{
						Data4: proto.String("test8"),
					}.Build(),
					"test3": testprotos.TestNested1_builder{
						Data4: proto.String("test12"),
					}.Build(),
				},
			}.Build(),
		},
		{
			explanation: "Fallback values",
			proto: testprotos.TestFallbackTypes_builder{
				Id:     proto.String("123"),
				Data1:  proto.Float64(2.2),
				Data2:  proto.Float32(3.3),
				Data3:  proto.Int32(4),
				Data4:  proto.Int64(5),
				Data5:  proto.Uint32(6),
				Data6:  proto.Uint64(7),
				Data7:  proto.Int32(8),
				Data8:  proto.Int64(9),
				Data9:  proto.Uint32(10),
				Data10: proto.Uint64(11),
				Data11: proto.Int32(12),
				Data12: proto.Int64(13),
				Data13: proto.Bool(false),
				Data14: proto.String("test111"),
				Data15: []byte("test222"),
			}.Build(),
			expected: testprotos.TestFallbackTypes_builder{
				Id:     proto.String("123"),
				Data1:  proto.Float64(1.0),
				Data2:  proto.Float32(1.0),
				Data3:  proto.Int32(1),
				Data4:  proto.Int64(1),
				Data5:  proto.Uint32(1),
				Data6:  proto.Uint64(1),
				Data7:  proto.Int32(1),
				Data8:  proto.Int64(1),
				Data9:  proto.Uint32(1),
				Data10: proto.Uint64(1),
				Data11: proto.Int32(1),
				Data12: proto.Int64(1),
				Data13: proto.Bool(true),
				Data14: proto.String("test"),
				Data15: []byte("test"),
			}.Build(),
		},
	} {
		p := New(fakeDeletedDataSubjectCrypter{})

		t.Run(tt.explanation, func(t *testing.T) {
			envelope, err := p.Encrypt(tt.proto)
			if err != nil {
				t.Fatalf("Error encrypting message: %v", err)
			}

			decrypted, err := p.Decrypt(envelope)
			if err != nil {
				t.Fatalf("Error decrypting message: %v", err)
			}

			if !proto.Equal(tt.expected, decrypted) {
				t.Error("Decrypted message with personal data removed does not match expected message")
			}
		})
	}
}
