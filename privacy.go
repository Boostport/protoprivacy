package protoprivacy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/Boostport/protoprivacy/internal/generated/boostport/privacy"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protopath"
	"google.golang.org/protobuf/reflect/protorange"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
)

type Privacy struct {
	mu      sync.Mutex
	cache   atomic.Pointer[messageCache]
	crypter Crypter
}

func (p *Privacy) loadMessage(m proto.Message) error {
	if validatedMessage, ok := (*p.cache.Load())[m.ProtoReflect().Descriptor()]; ok {
		return validatedMessage.err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	cache := *p.cache.Load()

	if validatedMessage, ok := cache[m.ProtoReflect().Descriptor()]; ok {
		return validatedMessage.err
	}

	cloned := cache.Clone()
	validatedMessageErr := validateMessage(m)
	cloned[m.ProtoReflect().Descriptor()] = &message{err: validatedMessageErr}

	p.cache.Store(&cloned)

	return validatedMessageErr
}

func (p *Privacy) Encrypt(ctx context.Context, message proto.Message) (*privacy.Envelope, error) {
	if err := p.loadMessage(message); err != nil {
		return nil, err
	}

	withoutPersonalData := proto.Clone(message)
	dataSubjectID, err := maskPersonalDataFieldsAndGetDataSubjectID(withoutPersonalData.ProtoReflect())
	if err != nil {
		return nil, fmt.Errorf("error clearing personal data fields: %w", err)
	}

	if dataSubjectID == nil {
		return nil, errors.New("message does not contain a data subject id")
	}

	marshaled, err := proto.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("error marshaling message: %w", err)
	}

	cipherText, err := p.crypter.Encrypt(ctx, *dataSubjectID, marshaled)
	if err != nil {
		return nil, fmt.Errorf("error encrypting message: %w", err)
	}

	anyMessage, err := anypb.New(withoutPersonalData)
	if err != nil {
		return nil, fmt.Errorf("error creating any message: %w", err)
	}

	return privacy.Envelope_builder{
		Message:       anyMessage,
		EncryptedData: cipherText,
	}.Build(), nil
}

func (p *Privacy) Decrypt(ctx context.Context, envelope *privacy.Envelope) (proto.Message, error) {

	message, err := envelope.GetMessage().UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling message: %w", err)
	}

	dataSubjectID, err := getDataSubjectID(message.ProtoReflect())
	if err != nil {
		return nil, fmt.Errorf("error getting data subject id: %w", err)
	}

	plainTextBytes, err := p.crypter.Decrypt(ctx, *dataSubjectID, envelope.GetEncryptedData())
	if err != nil {
		return nil, fmt.Errorf("error decrypting message: %w", err)
	}

	if plainTextBytes == nil {
		err := applyFallbackToPersonalDataFields(message.ProtoReflect())
		if err != nil {
			return nil, fmt.Errorf("error applying fallback to personal data fields: %w", err)
		}
	} else {
		decryptedMessage := message.ProtoReflect().New().Interface()

		err = proto.Unmarshal(plainTextBytes, decryptedMessage)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling decrypted message: %w", err)
		}

		return decryptedMessage, nil
	}

	return message, nil
}

func New(crypter Crypter) *Privacy {
	p := &Privacy{
		crypter: crypter,
	}

	p.cache.Store(&messageCache{})
	return p
}

func maskPersonalDataFieldsAndGetDataSubjectID(m protoreflect.Message) (*string, error) {
	var dataSubjectID *string

	err := protorange.Range(m, func(v protopath.Values) error {
		privacyField, fd := getPrivacyFieldOptions(v)

		if privacyField.HasDataSubjectId() {
			dataSubjectID = proto.String(fmt.Sprintf("%s%s", privacyField.GetDataSubjectId().GetPrefix(), v.Index(-1).Value.String()))
		} else if privacyField.HasPersonalData() {
			m, ok := v.Index(-2).Value.Interface().(protoreflect.Message)

			if !ok {
				return nil
			}

			if fd.IsMap() || fd.IsList() || fd.Message() != nil {
				m.Clear(fd)
			} else {
				m.Set(fd, fd.Default())
			}
		}

		return nil
	})

	return dataSubjectID, err
}

func getDataSubjectID(m protoreflect.Message) (*string, error) {
	var dataSubjectID *string

	err := protorange.Range(m, func(v protopath.Values) error {
		privacyField, _ := getPrivacyFieldOptions(v)

		if privacyField.HasDataSubjectId() {
			dataSubjectID = proto.String(fmt.Sprintf("%s%s", privacyField.GetDataSubjectId().GetPrefix(), v.Index(-1).Value.String()))
			return protorange.Terminate
		}

		return nil
	})

	return dataSubjectID, err
}

func applyFallbackToPersonalDataFields(m protoreflect.Message) error {
	err := protorange.Range(m, func(v protopath.Values) error {
		privacyField, fd := getPrivacyFieldOptions(v)

		personalData := privacyField.GetPersonalData()
		if personalData == nil {
			return nil
		}

		parentMessage, ok := v.Index(-2).Value.Interface().(protoreflect.Message)
		if !ok {
			return nil
		}

		if personalData.HasFallback() {
			var value any

			switch personalData.WhichFallback() {
			case privacy.PrivacyFieldOptions_PersonalData_FallbackDouble_case:
				value = personalData.GetFallbackDouble()
			case privacy.PrivacyFieldOptions_PersonalData_FallbackFloat_case:
				value = personalData.GetFallbackFloat()
			case privacy.PrivacyFieldOptions_PersonalData_FallbackInt32_case:
				value = personalData.GetFallbackInt32()
			case privacy.PrivacyFieldOptions_PersonalData_FallbackInt64_case:
				value = personalData.GetFallbackInt64()
			case privacy.PrivacyFieldOptions_PersonalData_FallbackUint32_case:
				value = personalData.GetFallbackUint32()
			case privacy.PrivacyFieldOptions_PersonalData_FallbackUint64_case:
				value = personalData.GetFallbackUint64()
			case privacy.PrivacyFieldOptions_PersonalData_FallbackSint32_case:
				value = personalData.GetFallbackSint32()
			case privacy.PrivacyFieldOptions_PersonalData_FallbackSint64_case:
				value = personalData.GetFallbackSint64()
			case privacy.PrivacyFieldOptions_PersonalData_FallbackFixed32_case:
				value = personalData.GetFallbackFixed32()
			case privacy.PrivacyFieldOptions_PersonalData_FallbackFixed64_case:
				value = personalData.GetFallbackFixed64()
			case privacy.PrivacyFieldOptions_PersonalData_FallbackSfixed32_case:
				value = personalData.GetFallbackSfixed32()
			case privacy.PrivacyFieldOptions_PersonalData_FallbackSfixed64_case:
				value = personalData.GetFallbackSfixed64()
			case privacy.PrivacyFieldOptions_PersonalData_FallbackBool_case:
				value = personalData.GetFallbackBool()
			case privacy.PrivacyFieldOptions_PersonalData_FallbackString_case:
				value = personalData.GetFallbackString()
			case privacy.PrivacyFieldOptions_PersonalData_FallbackBytes_case:
				value = personalData.GetFallbackBytes()
			}

			parentMessage.Set(fd, protoreflect.ValueOf(value))
		} else {
			parentMessage.Clear(fd)
		}

		return nil
	})

	return err
}

func getPrivacyFieldOptions(v protopath.Values) (*privacy.PrivacyFieldOptions, protoreflect.FieldDescriptor) {
	fd := v.Path.Index(-1).FieldDescriptor()
	if fd == nil {
		return nil, nil
	}

	privacyField := proto.GetExtension(fd.Options(), privacy.E_Field).(*privacy.PrivacyFieldOptions)
	if privacyField == nil {
		return nil, nil
	}

	return privacyField, fd
}
