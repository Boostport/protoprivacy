# protoprivacy
[![Tests](https://github.com/Boostport/protoprivacy/actions/workflows/tests.yml/badge.svg)](https://github.com/Boostport/protoprivacy/actions/workflows/tests.yml)

`protoprivacy` is a [Protocol Buffers](https://protobuf.dev/) library that allows data in protobuf message fields marked
as personal data to be rendered unreadable using [crypto-shredding](https://en.wikipedia.org/wiki/Crypto-shredding).
```
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│  Original message                                                        │
│  ────────────────                                                        │
│                                                                          │
│  string id = 1 [(boostport.privacy.data_subject_id).id = {}];            │
│                                                                          │
│  string private_data = 2 [(boostport.privacy.field).personal_data = {}]; │
│                                                                          │
│  string non_sensitive_data = 3;                                          │
│                                                                          │
└─────────────────┬───────────────────────────────────┬────────────────────┘
                  │                                   │                     
                  │ Personal data zeroed              │                     
                  │                                   │                     
┌─────────────────┼───────────────────────────────┐   │                     
│                 │                               │   │                     
│  Envelope       │                               │   │                     
│  ────────       │                               │   │                     
│                 ▼                               │   │                     
│  google.protobuf.Any message = 1;               │   │   Encrypted         
│                                                 │   │                     
│                                                 │   │                     
│  bytes encrypted_data = 2; ◄────────────────────┼───┘                     
│                                                 │                         
│                                                 │                         
└─────────────────────────────────────────────────┘                         
```
Fields containing personal data are marked with the `[(boostport.privacy.field).personal_data = {}]` annotation and the
field containing the data subject id is marked with the `[(boostport.privacy.data_subject_id).id = {}]` annotation. During
marshaling, the personal data fields' values are replaced with their default/zero values. The data subject id is used
to derive a key that is used to encrypt the original protobuf message containing sensitive data. The encrypted and redacted
messages are stored in a `protoprivacy.Envelope` message.

When unmarshaling, the data subject id to retrieve the key for decryption. If the key exists, the encrypted message is 
decrypted and the original message is returned. If the key has been deleted due to crypto-shredding, the message is
returned with personal data fields cleared or set to their fallback values if configured.

## Supported languages
- Go

## Usage
### Import
```protobuf
edition = "2023";
package my.package;
import "boostport/privacy/privacy.proto";
```

#### Build using [buf](https://buf.build/docs/cli/) (recommended)
Add `buf.build/boostport/protoprivacy` as a dependency to your `buf.yaml` file:
```yaml
version: v2
# <snip>
deps:
  - buf.build/boostport/protoprivacy
# <snip>
```
Then run `buf dep update` to update your dependencies.

#### Build using [protoc](https://github.com/protocolbuffers/protobuf)
Include the `proto/protoprivacy` folder in your `protoc` command:
```bash
$ protoc -I./vendor/github.com/Boostport/protovalidate -I=$SRC_DIR --go_out=$DST_DIR $SRC_DIR/myproto.proto
```

### Annotate messages
Given the following message:
```protobuf
message Address {
  string line1 = 1;
  string locality = 2;
  string administrative_area = 3;
  string post_code = 4;
  string country = 5;
  
}
message UserCreated {
  string id = 1;
  google.protobuf.timestamp created_at = 2;
  string first_name = 3;
  string last_name = 4;
  string email_address = 5;
  Address address = 6;
  
}
```

Mark the field containing your data subject id with the `[(boostport.privacy.data_subject_id).id = {}]` annotation. There
can only be one data subject id annotation in your message, and it must be a `string` or `numeric` field. The data subject
id can be in a nested message, but none of its parents can be a map or repeated field. In addition, a prefix can be set
for the data subject id. This prefix can be used by your crypter to derive sub-keys which can be used to group data to
selectively delete a user's data.

Any field containing personal data should be marked with the `[(boostport.privacy.field).personal_data = {}]`
annotation. These can be any field type including nested messages, maps, and repeated fields. A fallback value can also
be set, with the fallback type corresponding to the field type. Note that fallback values can only be set for scalar fields.

Given the above message, we can annotate it as follows:
```protobuf 
message Address {
  string line1 = 1 [(boostport.privacy.field).personal_data = {}];
  string locality = 2 [(boostport.privacy.field).personal_data = {}];
  string administrative_area = 3 [(boostport.privacy.field).personal_data = {}];
  string post_code = 4 [(boostport.privacy.field).personal_data = {}];
  string country = 5;
  
}
message UserCreated {
  string id = 1 [(boostport.privacy.data_subject_id).id = {prefix: "user:"}];
  google.protobuf.timestamp created_at = 2;
  string first_name = 3 [(boostport.privacy.field).personal_data = {fallback_string: "ANONYMOUS"}];
  string last_name = 4 [(boostport.privacy.field).personal_data = {fallback_string: "USER"}];
  string email_address = 5 [(boostport.privacy.field).personal_data = {fallback_string: "anonymous@example.com"}];
  Address address = 6;
  
}
```

### Implement crypter
In order to encrypt and decrypt messages, you need to implement a crypter. The crypter is supplied the data subject id
and the bytes to encrypt or decrypt. The crypter is responsible for deriving the key from the data subject id and the
implementation of the encryption and decryption functions is left to the implementer. We are unable to ship a concrete
implementation of a crypter as it is dependent on the use case and the encryption algorithm used. 

For implementing your encryption and decryption functions, we recommend using the following libraries:
- [Google Tink](https://developers.google.com/tink) (Various language implementations available)
- [nacl](https://nacl.cr.yp.to/) (Various language implementations available)

### Use the privacy library (Go)
```go
func main(){
    c := &MyCrypter{}
    p := privacy.New(c)
	
    msg := proto.UserCreated_builder{
        Id: proto.String("123456789"),	
        CreatedAt: timestamppb.Now(),
        FirstName: proto.String("John"),
        LastName: proto.String("Doe"),
        EmailAddress: proto.String("john@example.com"),
        Address: &proto.Address_builder{
            Line1: proto.String("123 Example St"),
            Locality: proto.String("Melbourne"),
            AdministrativeArea: proto.String("VIC"),
            PostCode: proto.String("3000"),
            Country: proto.String("AU"),
        },
    }.Build()
	
    encrypted, err := p.Encrypt(msg)
	if err != nil {
        panic(err)
    }
	
    decrypted, err := p.Decrypt(encrypted)
	if err != nil {
        panic(err)
    }
	
    fmt.Println(decrypted) // Encrypted fields decrypted and returned
	
    c.DeleteKey("user:123456789")
	
    decrypted, err = p.Decrypt(encrypted)
    if err != nil {
        panic(err)
    }
	
    fmt.Println(decrypted) // Encrypted fields cleared or set to fallback values
}
```

## Development
### Compile protobuf
Run `go generate` from the root of the repository.

### Run tests
Run `go test -v -race ./...` from the root of the repository.