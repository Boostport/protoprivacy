package protoprivacy

import "errors"

var PersonalDataDeleted = errors.New("personal data deleted")

type Crypter interface {
	Encrypt(dataSubjectID string, cleartext []byte) ([]byte, error)
	Decrypt(dataSubjectID string, ciphertext []byte) ([]byte, error)
}
