package protoprivacy

import "google.golang.org/protobuf/reflect/protoreflect"

type message struct {
	hasPrivacyFields bool
	err              error
}

type messageCache map[protoreflect.MessageDescriptor]*message

func (c messageCache) Clone() messageCache {
	clone := make(messageCache)
	for k, v := range c {
		clone[k] = v
	}
	return clone
}
