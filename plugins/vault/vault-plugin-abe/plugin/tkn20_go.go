package abe

/*
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

// Define a struct to return dynamic array results
typedef struct {
    uint8_t* data;
    size_t len;
} CByteArray;
*/
import "C"
import (
	"regexp"
	"strings"
	"unsafe"

	"github.com/cloudflare/circl/abe/cpabe/tkn20"
)

// normalizePolicy converts uppercase AND/OR/NOT keywords to lowercase
// so the CIRCL TKN20 DSL lexer can recognize them.
func normalizePolicy(policy string) string {
	re := regexp.MustCompile(`\b(AND|OR|NOT)\b`)
	return re.ReplaceAllStringFunc(policy, strings.ToLower)
}

// Utility function to convert Go byte array to C
func toCByteArray(data []byte) C.CByteArray {
	if len(data) == 0 {
		return C.CByteArray{data: nil, len: 0}
	}
	return C.CByteArray{
		data: (*C.uint8_t)(C.CBytes(data)),
		len:  C.size_t(len(data)),
	}
}

// Free byte array (avoid memory leak when used on C++)
//
//export TKN20_FreeByteArray
func TKN20_FreeByteArray(arr C.CByteArray) {
	if arr.data != nil {
		C.free(unsafe.Pointer(arr.data))
	}
}

//export TKN20_Setup
// Setup initializes the system, returning the Public Key (for encryption) and Master Secret Key (for decryption key generation)
func TKN20_Setup(pubKeyOut *C.CByteArray, mskOut *C.CByteArray) C.int {
	pk, msk, err := tkn20.Setup(nil)
	if err != nil {
		return -1
	}

	pkBytes, _ := pk.MarshalBinary()
	mskBytes, _ := msk.MarshalBinary()

	*pubKeyOut = toCByteArray(pkBytes)
	*mskOut = toCByteArray(mskBytes)
	return 0
}

//export TKN20_KeyGen
// Generate decryption key (Attribute Key) based on the attribute set passed as a string (e.g., "A:1,B:2,ROLE:admin")
func TKN20_KeyGen(mskBytes *C.uint8_t, mskLen C.size_t, attrsStr *C.char, attrKeyOut *C.CByteArray) C.int {
	mskData := C.GoBytes(unsafe.Pointer(mskBytes), C.int(mskLen))
	var msk tkn20.SystemSecretKey
	if err := msk.UnmarshalBinary(mskData); err != nil {
		return -1
	}

	// Parse attribute string
	attrStrGo := C.GoString(attrsStr)
	attrMap := make(map[string]string)
	if attrStrGo != "" {
		pairs := strings.Split(attrStrGo, ",")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, ":", 2)
			if len(kv) == 2 {
				attrMap[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			} else {
				attrMap[strings.TrimSpace(kv[0])] = "" // Trường hợp không có giá trị
			}
		}
	}

	var attrs tkn20.Attributes
	attrs.FromMap(attrMap)

	ak, err := msk.KeyGen(nil, attrs)
	if err != nil {
		return -1
	}

	akBytes, _ := ak.MarshalBinary()
	*attrKeyOut = toCByteArray(akBytes)
	return 0
}

//export TKN20_Encrypt
// Encrypt message based on the policy (Policy). Example policyStr: "A:1 AND B:2"
func TKN20_Encrypt(pkBytes *C.uint8_t, pkLen C.size_t, policyStr *C.char, msgBytes *C.uint8_t, msgLen C.size_t, ctOut *C.CByteArray) C.int {
	pkData := C.GoBytes(unsafe.Pointer(pkBytes), C.int(pkLen))
	var pk tkn20.PublicKey
	if err := pk.UnmarshalBinary(pkData); err != nil {
		return -1
	}

	var policy tkn20.Policy
	if err := policy.FromString(normalizePolicy(C.GoString(policyStr))); err != nil {
		return -1
	}

	msgData := C.GoBytes(unsafe.Pointer(msgBytes), C.int(msgLen))
	ct, err := pk.Encrypt(nil, policy, msgData)
	if err != nil {
		return -1
	}

	*ctOut = toCByteArray(ct)
	return 0
}

//export TKN20_Decrypt
// Decrypt ciphertext using Attribute Key (Attribute Key)
func TKN20_Decrypt(akBytes *C.uint8_t, akLen C.size_t, ctBytes *C.uint8_t, ctLen C.size_t, msgOut *C.CByteArray) C.int {
	akData := C.GoBytes(unsafe.Pointer(akBytes), C.int(akLen))
	var ak tkn20.AttributeKey
	if err := ak.UnmarshalBinary(akData); err != nil {
		return -1
	}

	ctData := C.GoBytes(unsafe.Pointer(ctBytes), C.int(ctLen))
	msg, err := ak.Decrypt(ctData)
	if err != nil {
		return -1
	}

	*msgOut = toCByteArray(msg)
	return 0
}

