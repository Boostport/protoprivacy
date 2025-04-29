package protoprivacy

import (
	"context"
	"errors"
)

var PersonalDataDeleted = errors.New("personal data deleted")

type Crypter interface {
	Encrypt(ctx context.Context, dataSubjectID string, cleartext []byte) ([]byte, error)
	Decrypt(ctx context.Context, dataSubjectID string, ciphertext []byte) ([]byte, error)
}
