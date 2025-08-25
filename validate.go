package protoprivacy

import (
	"errors"
	"fmt"

	"github.com/Boostport/protoprivacy/internal/generated/boostport/privacy"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func validateMessage(message proto.Message) (bool, error) {

	var errs error

	reflect := message.ProtoReflect().Descriptor()

	numDataSubjectIDs := 0
	numPersonalData := 0
	hasNonNumericOrNonStringDataSubjectID := false

	walkFields(reflect, func(f protoreflect.FieldDescriptor) bool {

		// Each message can only have 1 data subject id
		if fieldHasDataSubjectID(f) {
			numDataSubjectIDs++
		}

		// Data subject id field must be a string or number
		if fieldHasDataSubjectID(f) && (!fieldIsNumeric(f) && !fieldIsString(f) || f.IsMap() || f.IsList()) {
			hasNonNumericOrNonStringDataSubjectID = true
		}

		// Message must have at least one personal data field nested or at the top level
		if fieldHasPersonalData(f) {
			numPersonalData++
		}

		// Repeated field cannot have a child that is a data subject id
		if messageType := f.Message(); f.IsList() && messageType != nil {
			walkFields(messageType, func(childField protoreflect.FieldDescriptor) bool {
				if fieldHasDataSubjectID(childField) {
					errs = errors.Join(errs, fmt.Errorf("repeated field %s in %s has child field %s in %s that is a data subject id in %s", f.FullName(), messageType.FullName(), childField.FullName(), childField.Parent().FullName(), reflect.ParentFile().Path()))
				}
				return false
			})
		}

		// Map field cannot have a child that is a data subject id
		if mapValue := f.MapValue(); f.IsMap() && mapValue != nil && mapValue.Message() != nil {
			walkFields(mapValue.Message(), func(childField protoreflect.FieldDescriptor) bool {
				if fieldHasDataSubjectID(childField) {
					errs = errors.Join(errs, fmt.Errorf("map field %s in %s has child field %s in %s that is a data subject id in %s", f.FullName(), mapValue.Message().FullName(), childField.FullName(), childField.Parent().FullName(), reflect.ParentFile().Path()))
				}
				return false
			})
		}

		// Fallback value (if set) must have the same type as the field
		if fieldHasPersonalData(f) && fieldHasFallback(f) && fieldFallbackKind(f) != f.Kind() {
			errs = errors.Join(errs, fmt.Errorf("field %s in message %s has a fallback value with type %s but the field has type %s in %s", f.FullName(), reflect.FullName(), fieldFallbackKind(f), f.Kind(), reflect.ParentFile().Path()))
		}

		return false
	})

	if numDataSubjectIDs == 0 && numPersonalData == 0 {
		return false, errs
	}

	if numDataSubjectIDs > 1 {
		errs = errors.Join(errs, fmt.Errorf("message %s has more than one field with the data_subject_id field option in %s", reflect.FullName(), reflect.ParentFile().Path()))
	}

	if numDataSubjectIDs <= 0 {
		errs = errors.Join(errs, fmt.Errorf("message %s does not have a field with the data_subject_id field option in %s", reflect.FullName(), reflect.ParentFile().Path()))
	}

	if hasNonNumericOrNonStringDataSubjectID {
		errs = errors.Join(errs, fmt.Errorf("message %s has a field with the data_subject_id field option that is not a simple string or numeric in %s", reflect.FullName(), reflect.ParentFile().Path()))
	}

	if numPersonalData <= 0 {
		errs = errors.Join(errs, fmt.Errorf("message %s must have at least 1 field with the personal_data field option in %s", reflect.FullName(), reflect.ParentFile().Path()))
	}

	return true, errs
}

// walkFields walks all fields in a message and calls the provided function for each field. If the function returns true, the walk is stopped.
func walkFields(msg protoreflect.MessageDescriptor, f func(protoreflect.FieldDescriptor) bool) {

	fields := msg.Fields()

	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)

		if field.Kind() == protoreflect.MessageKind {
			walkFields(field.Message(), f)
		}

		if f(field) {
			return
		}
	}
}

func fieldHasDataSubjectID(f protoreflect.FieldDescriptor) bool {
	options := f.Options()

	if options == nil {
		return false
	}

	if privacyField := proto.GetExtension(options, privacy.E_Field).(*privacy.PrivacyFieldOptions); privacyField != nil {
		if privacyField.HasDataSubjectId() {
			return true
		}
	}

	return false
}

func fieldHasPersonalData(f protoreflect.FieldDescriptor) bool {
	options := f.Options()

	if options == nil {
		return false
	}

	if privacyField := proto.GetExtension(options, privacy.E_Field).(*privacy.PrivacyFieldOptions); privacyField != nil {
		if privacyField.HasPersonalData() {
			return true
		}
	}

	return false
}

func fieldIsNumeric(f protoreflect.FieldDescriptor) bool {
	switch f.Kind() {
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Uint32Kind, protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Uint64Kind, protoreflect.Sfixed32Kind, protoreflect.Fixed32Kind, protoreflect.FloatKind, protoreflect.Sfixed64Kind, protoreflect.Fixed64Kind, protoreflect.DoubleKind:
		return true
	}

	return false
}

func fieldIsString(f protoreflect.FieldDescriptor) bool {
	switch f.Kind() {
	case protoreflect.StringKind:
		return true
	}

	return false
}

func fieldHasFallback(f protoreflect.FieldDescriptor) bool {
	options := f.Options()

	if options == nil {
		return false
	}

	privacyField := proto.GetExtension(options, privacy.E_Field).(*privacy.PrivacyFieldOptions)
	if privacyField == nil {
		return false
	}

	personalData := privacyField.GetPersonalData()
	if personalData == nil {
		return false
	}

	return personalData.HasFallback()
}

func fieldFallbackKind(f protoreflect.FieldDescriptor) protoreflect.Kind {
	options := f.Options()

	if options == nil {
		return 0
	}

	privacyField := proto.GetExtension(options, privacy.E_Field).(*privacy.PrivacyFieldOptions)
	if privacyField == nil {
		return 0
	}

	personalData := privacyField.GetPersonalData()
	if personalData == nil {
		return 0
	}

	switch {
	case personalData.HasFallbackBool():
		return protoreflect.BoolKind
	case personalData.HasFallbackInt32():
		return protoreflect.Int32Kind
	case personalData.HasFallbackSint32():
		return protoreflect.Sint32Kind
	case personalData.HasFallbackUint32():
		return protoreflect.Uint32Kind
	case personalData.HasFallbackInt64():
		return protoreflect.Int64Kind
	case personalData.HasFallbackSint64():
		return protoreflect.Sint64Kind
	case personalData.HasFallbackUint64():
		return protoreflect.Uint64Kind
	case personalData.HasFallbackSfixed32():
		return protoreflect.Sfixed32Kind
	case personalData.HasFallbackFixed32():
		return protoreflect.Fixed32Kind
	case personalData.HasFallbackFloat():
		return protoreflect.FloatKind
	case personalData.HasFallbackSfixed64():
		return protoreflect.Sfixed64Kind
	case personalData.HasFallbackFixed64():
		return protoreflect.Fixed64Kind
	case personalData.HasFallbackDouble():
		return protoreflect.DoubleKind
	case personalData.HasFallbackString():
		return protoreflect.StringKind
	case personalData.HasFallbackBytes():
		return protoreflect.BytesKind
	}

	return 0
}
