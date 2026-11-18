//go:build js && wasm

package main

import (
	"regexp"
	"strings"
	"syscall/js"

	"github.com/cloudflare/circl/abe/cpabe/tkn20"
)

func jsBytes(v js.Value) []byte {
	b := make([]byte, v.Get("byteLength").Int())
	js.CopyBytesToGo(b, v)
	return b
}

func jsResult(values ...[]byte) interface{} {
	result := js.Global().Get("Array").New(len(values))
	for i, value := range values {
		array := js.Global().Get("Uint8Array").New(len(value))
		js.CopyBytesToJS(array, value)
		result.SetIndex(i, array)
	}
	return result
}

func callTKN20(_ js.Value, args []js.Value) (result interface{}) {
	// An invalid key/ciphertext must not tear down the persistent Go runtime.
	defer func() {
		if recover() != nil {
			result = nil
		}
	}()
	switch args[0].Int() {
	case 0:
		pk, msk, err := tkn20.Setup(nil)
		if err != nil {
			return nil
		}
		p, err := pk.MarshalBinary()
		if err != nil {
			return nil
		}
		m, err := msk.MarshalBinary()
		if err != nil {
			return nil
		}
		return jsResult(p, m)
	case 1:
		var msk tkn20.SystemSecretKey
		if msk.UnmarshalBinary(jsBytes(args[1])) != nil {
			return nil
		}
		attributes := make(map[string]string)
		if text := args[2].String(); text != "" {
			for _, pair := range strings.Split(text, ",") {
				kv := strings.SplitN(pair, ":", 2)
				value := ""
				if len(kv) == 2 {
					value = strings.TrimSpace(kv[1])
				}
				attributes[strings.TrimSpace(kv[0])] = value
			}
		}
		var attrs tkn20.Attributes
		attrs.FromMap(attributes)
		key, err := msk.KeyGen(nil, attrs)
		if err != nil {
			return nil
		}
		data, err := key.MarshalBinary()
		if err != nil {
			return nil
		}
		return jsResult(data)
	case 2:
		var pk tkn20.PublicKey
		if pk.UnmarshalBinary(jsBytes(args[1])) != nil {
			return nil
		}
		var policy tkn20.Policy
		re := regexp.MustCompile(`\b(AND|OR|NOT)\b`)
		text := re.ReplaceAllStringFunc(args[2].String(), strings.ToLower)
		if policy.FromString(text) != nil {
			return nil
		}
		data, err := pk.Encrypt(nil, policy, jsBytes(args[3]))
		if err != nil {
			return nil
		}
		return jsResult(data)
	case 3:
		var key tkn20.AttributeKey
		if key.UnmarshalBinary(jsBytes(args[1])) != nil {
			return nil
		}
		data, err := key.Decrypt(jsBytes(args[3]))
		if err != nil {
			return nil
		}
		return jsResult(data)
	}
	return nil
}

func main() {
	callback := js.FuncOf(callTKN20)
	js.Global().Set("__hybridTKN20", callback)
	select {}
}
