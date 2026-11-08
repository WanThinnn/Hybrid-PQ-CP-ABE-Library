package abe

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func readPublicAuthority(t *testing.T, b logical.Backend, storage logical.Storage, format string) map[string]interface{} {
	t.Helper()
	response, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "authority", Storage: storage,
		Data: map[string]interface{}{"public_key_format": format},
	})
	if err != nil || response == nil || response.IsError() {
		t.Fatal("public authority read failed", err)
	}
	return response.Data
}

func TestPublicAuthorityRecoveryAndReference(t *testing.T) {
	for _, scheme := range []string{"ac17", "tkn20", "covercrypt"} {
		t.Run(scheme, func(t *testing.T) {
			b, storage := newTestBackend(t)
			params := map[string]interface{}{"scheme": scheme, "pqc": true, "create_only": true, "public_key_format": "reference"}
			if scheme == "covercrypt" {
				params["config_json"] = strings.ReplaceAll(testConfig, ",", ",\n  ")
			}
			setup := request(t, b, storage, "setup", params, false)
			before, _ := storage.Get(context.Background(), authorityKey)
			public := readPublicAuthority(t, b, storage, "reference")
			if public["public_key"] != setup["public_key"] || public["revision"] != setup["revision"] || public["pqc_public_key"] != setup["pqc_public_key"] {
				t.Fatal("recovery changed public identity")
			}
			allowed := map[string]bool{"public_key": true, "public_key_format": true, "public_key_fingerprint": true,
				"contract_version": true, "scheme": true, "pqc": true, "native_version": true, "revision": true,
				"pqc_public_key": true, "config_json": true, "mode": true}
			for field := range public {
				if !allowed[field] {
					t.Fatal("unexpected public response field", field)
				}
			}
			after, _ := storage.Get(context.Background(), authorityKey)
			if !bytes.Equal(before.Value, after.Value) {
				t.Fatal("recovery modified storage")
			}
			request(t, b, storage, "setup", params, true)
			unchanged, _ := storage.Get(context.Background(), authorityKey)
			if !bytes.Equal(before.Value, unchanged.Value) {
				t.Fatal("create_only replaced authority")
			}
			inline := readPublicAuthority(t, b, storage, "base64")
			raw, err := base64.StdEncoding.DecodeString(inline["public_key"].(string))
			if err != nil || len(raw) == 0 || inline["public_key_fingerprint"] != public["public_key_fingerprint"] {
				t.Fatal("Base64 compatibility failed")
			}
			attrs, policy := "admin", "admin"
			if scheme == "tkn20" {
				attrs, policy = "role:admin", "role:admin"
			}
			if scheme == "covercrypt" {
				attrs, policy = "Department::IT Level::ADMIN", "Department::IT && Level::ADMIN"
			}
			key := request(t, b, storage, "genkey", map[string]interface{}{"scheme": scheme, "attributes": attrs}, false)
			for _, signed := range []bool{false, true} {
				cipher := request(t, b, storage, "encrypt", map[string]interface{}{"scheme": scheme, "public_key": public["public_key"], "plaintext": "aGVsbG8=", "policy": policy, "sign": signed}, false)
				metadata := cipher["crypto_metadata"].(map[string]interface{})
				if metadata["scheme"] != scheme || metadata["pqc_signed"] != signed || metadata["format"] != "hybrid-v2" || metadata["keyset_id"] != public["public_key_fingerprint"] || metadata["authority_revision"] != public["revision"] {
					t.Fatal("incorrect encryption metadata")
				}
				payload := map[string]interface{}{"secret_key": key["secret_key"], "ciphertext": cipher["ciphertext"]}
				if signed {
					payload["pqc_public_key"] = public["pqc_public_key"]
				}
				if request(t, b, storage, "decrypt", payload, false)["plaintext"] != "aGVsbG8=" {
					t.Fatal("round trip failed")
				}
			}
			for _, ref := range []string{publicKeyReferencePrefix + strings.Repeat("0", 64), publicKeyReferencePrefix + "../wrong", publicKeyReferencePrefix + strings.ToUpper(public["public_key_fingerprint"].(string))} {
				request(t, b, storage, "encrypt", map[string]interface{}{"scheme": scheme, "public_key": ref, "plaintext": "aGVsbG8=", "policy": policy}, true)
			}
			other := "covercrypt"
			if scheme == other {
				other = "ac17"
			}
			request(t, b, storage, "encrypt", map[string]interface{}{"scheme": other, "public_key": public["public_key"], "plaintext": "aGVsbG8=", "policy": policy}, true)
		})
	}
}

func TestPublicAuthorityMissingAndReadOnly(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()
	response, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "authority", Storage: storage})
	if err != nil || response != nil {
		t.Fatal("missing authority must return not found")
	}
	response, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "authority", Storage: storage})
	if err == nil && (response == nil || !response.IsError()) {
		t.Fatal("authority endpoint accepted a write")
	}
	for _, path := range []string{authorityKey, "msk/abe", "msk/pqc", "config/abe"} {
		storage.Put(ctx, &logical.StorageEntry{Key: path, Value: []byte("incomplete-state")})
		request(t, b, storage, "setup", map[string]interface{}{"create_only": true}, true)
		storage.Delete(ctx, path)
	}
}

func TestConcurrentCreateOnly(t *testing.T) {
	b, storage := newTestBackend(t)
	var group sync.WaitGroup
	results := make(chan bool, 4)
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			response, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation, Path: "setup", Storage: storage, Data: map[string]interface{}{"scheme": "ac17", "create_only": true},
			})
			results <- err == nil && response != nil && !response.IsError()
		}()
	}
	group.Wait()
	close(results)
	success := 0
	for result := range results {
		if result {
			success++
		}
	}
	if success != 1 {
		t.Fatal("create_only did not select one initializer", success)
	}
}

func TestRetiredChunkAuthorityCryptoCompatibility(t *testing.T) {
	b, storage := newTestBackend(t)
	setup := request(t, b, storage, "setup", map[string]interface{}{"scheme": "covercrypt", "config_json": testConfig, "pqc": true}, false)
	oldUser := request(t, b, storage, "genkey", map[string]interface{}{"scheme": "covercrypt", "attributes": "Department::IT Level::ADMIN"}, false)
	oldCipher := request(t, b, storage, "encrypt", map[string]interface{}{"scheme": "covercrypt", "public_key": setup["public_key"], "plaintext": "aGVsbG8=", "policy": "Department::IT && Level::ADMIN"}, false)
	state, err := loadAuthority(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}
	storeRetiredChunkFixture(t, storage, state)
	config := logical.TestBackendConfig()
	config.StorageView = storage
	reloaded, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reloaded.Cleanup(context.Background()) })
	public := readPublicAuthority(t, reloaded, storage, "reference")
	if public["public_key"] != state.publicKeyReference() {
		t.Fatal("retired public reference changed")
	}
	request(t, reloaded, storage, "decrypt", map[string]interface{}{"secret_key": oldUser["secret_key"], "ciphertext": oldCipher["ciphertext"], "pqc_public_key": setup["pqc_public_key"]}, false)
	user := request(t, reloaded, storage, "genkey", map[string]interface{}{"scheme": "covercrypt", "attributes": "Department::IT Level::ADMIN"}, false)
	wrong := request(t, reloaded, storage, "genkey", map[string]interface{}{"scheme": "covercrypt", "attributes": "Department::HR"}, false)
	cipher := request(t, reloaded, storage, "encrypt", map[string]interface{}{"scheme": "covercrypt", "public_key": public["public_key"], "plaintext": "aGVsbG8=", "policy": "Department::IT && Level::ADMIN"}, false)
	request(t, reloaded, storage, "decrypt", map[string]interface{}{"secret_key": user["secret_key"], "ciphertext": cipher["ciphertext"], "pqc_public_key": setup["pqc_public_key"]}, false)
	request(t, reloaded, storage, "decrypt", map[string]interface{}{"secret_key": wrong["secret_key"], "ciphertext": cipher["ciphertext"], "pqc_public_key": setup["pqc_public_key"]}, true)
	grown := request(t, reloaded, storage, "add_dimension", map[string]interface{}{"dimension_json": `{"name":"E","attributes":["yes","no"]}`}, false)
	if grown["pqc_public_key"] != setup["pqc_public_key"] {
		t.Fatal("growth replaced signing keys")
	}
	request(t, reloaded, storage, "encrypt", map[string]interface{}{"scheme": "covercrypt", "public_key": public["public_key"], "plaintext": "aGVsbG8=", "policy": "Department::IT"}, true)
	request(t, reloaded, storage, "decrypt", map[string]interface{}{"secret_key": user["secret_key"], "ciphertext": cipher["ciphertext"], "pqc_public_key": setup["pqc_public_key"]}, false)
}

func TestExplicitSigningValidation(t *testing.T) {
	b, storage := newTestBackend(t)
	setup := request(t, b, storage, "setup", map[string]interface{}{"scheme": "ac17"}, false)
	params := map[string]interface{}{"scheme": "ac17", "public_key": setup["public_key"], "plaintext": "aGVsbG8=", "policy": "admin", "sign": true}
	request(t, b, storage, "encrypt", params, true)
	params["sign"] = false
	params["pqc_private_key"] = "c3ludGhldGlj"
	request(t, b, storage, "encrypt", params, true)
	request(t, b, storage, "setup", map[string]interface{}{"public_key_format": "unsupported"}, true)
}
