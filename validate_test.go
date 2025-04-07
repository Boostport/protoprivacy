package protoprivacy

import (
	"testing"

	testprotos "github.com/Boostport/protoprivacy/internal/generated/boostport/privacy/testing"
	"google.golang.org/protobuf/proto"
)

func TestInvalidMessages(t *testing.T) {
	for _, tt := range []struct {
		explanation string
		message     proto.Message
	}{
		{
			explanation: "Message must not have multiple data subject ids",
			message:     &testprotos.InvalidMultipleDataSubjectIDs{},
		},
		{
			explanation: "Message must not have multiple data subject ids with nesting",
			message:     &testprotos.InvalidMultipleDataSubjectIDsWithNesting{},
		},
		{
			explanation: "Message must not have multiple data subject ids with deep nesting",
			message:     &testprotos.InvalidMultipleDataSubjectIDsWithDeepNesting{},
		},
		{
			explanation: "Message must not have multiple data subject ids with prefix",
			message:     &testprotos.InvalidMultipleDataSubjectIDsWithPrefix{},
		},
		{
			explanation: "Data subject id must not be repeated field",
			message:     &testprotos.InvalidDataSubjectIDRepeated{},
		},
		{
			explanation: "Data subject id must not be map field",
			message:     &testprotos.InvalidDataSubjectIDMap{},
		},
		{
			explanation: "Data subject id must not be message field",
			message:     &testprotos.InvalidDataSubjectIDMessage{},
		},
		{
			explanation: "Data subject id must not be child field in repeated field",
			message:     &testprotos.InvalidDataSubjectIDNestedInRepeated{},
		},
		{
			explanation: "Data subject id must not be child field in map field",
			message:     &testprotos.InvalidDataSubjectIDNestedInMap{},
		},
		{
			explanation: "Data subject id must not be child field in repeated external message",
			message:     &testprotos.InvalidDataSubjectIDInExternalNestedInRepeated{},
		},
		{
			explanation: "Data subject id must not be child field in external message in map",
			message:     &testprotos.InvalidDataSubjectIDInExternalNestedInMap{},
		},
		{
			explanation: "Message must contain at least one personal data field",
			message:     &testprotos.InvalidNoPersonalDataField{},
		},
		{
			explanation: "Fallback type must match field type",
			message:     &testprotos.InvalidFallbackTypes{},
		},
	} {
		t.Run(tt.explanation, func(t *testing.T) {
			err := validateMessage(tt.message)

			if err == nil {
				t.Error("Expected error, but invalid message passed validation")
			}
		})
	}
}

func TestValidMessages(t *testing.T) {
	for _, tt := range []struct {
		explanation string
		message     proto.Message
	}{
		{
			explanation: "Valid data subject id",
			message:     &testprotos.ValidDataSubjectID{},
		},
		{
			explanation: "Data subject id with prefix",
			message:     &testprotos.ValidDataSubjectIDWithPrefix{},
		},
		{
			explanation: "Data subject id in nested message",
			message:     &testprotos.ValidDataSubjectIDInNestedMessage{},
		},
		{
			explanation: "Data subject id int32",
			message:     &testprotos.ValidDataSubjectIDInt32{},
		},
		{
			explanation: "Data subject id sint32",
			message:     &testprotos.ValidDataSubjectIDSint32{},
		},
		{
			explanation: "Data subject id uint32",
			message:     &testprotos.ValidDataSubjectIDUint32{},
		},
		{
			explanation: "Data subject id int64",
			message:     &testprotos.ValidDataSubjectIDInt64{},
		},
		{
			explanation: "Data subject id sint64",
			message:     &testprotos.ValidDataSubjectIDSint64{},
		},
		{
			explanation: "Data subject id uint64",
			message:     &testprotos.ValidDataSubjectIDUint64{},
		},
		{
			explanation: "Data subject id sfixed32",
			message:     &testprotos.ValidDataSubjectIDSfixed64{},
		},
		{
			explanation: "Data subject id fixed32",
			message:     &testprotos.ValidDataSubjectIDFixed32{},
		},
		{
			explanation: "Data subject id float",
			message:     &testprotos.ValidDataSubjectIDFloat{},
		},
		{
			explanation: "Data subject id sfixed64",
			message:     &testprotos.ValidDataSubjectIDSfixed64{},
		},
		{
			explanation: "Data subject id double",
			message:     &testprotos.ValidDataSubjectIDDouble{},
		},
		{
			explanation: "Personal data is message",
			message:     &testprotos.ValidPersonalDataIsMessage{},
		},
		{
			explanation: "Personal data in nested message",
			message:     &testprotos.ValidPersonalDataInNestedMessage{},
		},
		{
			explanation: "Multiple personal data",
			message:     &testprotos.ValidMultiplePersonalData{},
		},
		{
			explanation: "Valid fallback types",
			message:     &testprotos.ValidFallbackTypes{},
		},
	} {
		t.Run(tt.explanation, func(t *testing.T) {
			err := validateMessage(tt.message)

			if err != nil {
				t.Errorf("Unexpected validation failure: %s", err)
			}
		})
	}
}
