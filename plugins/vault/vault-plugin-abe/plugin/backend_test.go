package abe

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// Storage is in memory, but every setup/keygen/encrypt/decrypt operation calls
// the actual shared native library through the production Vault request path.
func newTestBackend(t *testing.T) (logical.Backend, *logical.InmemStorage) {
	t.Helper()
	storage := &logical.InmemStorage{}
	config := logical.TestBackendConfig()
	config.StorageView = storage
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Cleanup(context.Background()) })
	return b, storage
}

func request(t *testing.T, b logical.Backend, storage logical.Storage, path string, data map[string]interface{}, denied bool) map[string]interface{} {
	t.Helper()
	response, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: path, Data: data, Storage: storage,
	})
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if response == nil || response.IsError() != denied {
		t.Fatalf("%s: denied=%v response=%#v", path, denied, response)
	}
	return response.Data
}

const testConfig = `{"dimensions":[{"name":"Department","attributes":["IT","HR"]},{"name":"Level","attributes":["USER","ADMIN"]}]}`

func TestAllSchemesAndSignatures(t *testing.T) {
	cases := []struct{ scheme, attributes, policy, denied string }{
		{"ac17", "admin it", "admin and it", "guest"},
		{"tkn20", "role:admin,dept:it", "role:admin and dept:it", "role:guest"},
		{"covercrypt", "Department::IT Level::ADMIN", "Department::IT && Level::ADMIN", "Department::IT"},
	}
	for _, tc := range cases {
		for _, signed := range []bool{false, true} {
			label := tc.scheme
			if signed {
				label += "/signed"
			}
			t.Run(label, func(t *testing.T) {
				b, storage := newTestBackend(t)
				params := map[string]interface{}{"scheme": tc.scheme, "pqc": signed}
				if tc.scheme == "covercrypt" {
					params["config_json"] = testConfig
				}
				setup := request(t, b, storage, "setup", params, false)
				version, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "VERSION"))
				if err != nil {
					t.Fatal(err)
				}
				if setup["native_version"] != strings.TrimSpace(string(version)) {
					t.Fatal("plugin loaded a stale core", setup["native_version"])
				}
				if _, exposed := setup["master_key"]; exposed {
					t.Fatal("setup exposed master key")
				}
				key := request(t, b, storage, "genkey", map[string]interface{}{"scheme": tc.scheme, "attributes": tc.attributes}, false)
				wrong := request(t, b, storage, "genkey", map[string]interface{}{"scheme": tc.scheme, "attributes": tc.denied}, false)
				plain := base64.StdEncoding.EncodeToString([]byte("Vault real crypto\x00\xff"))
				cipher := request(t, b, storage, "encrypt", map[string]interface{}{"scheme": tc.scheme, "public_key": setup["public_key"], "plaintext": plain, "policy": tc.policy}, false)
				data := map[string]interface{}{"ciphertext": cipher["ciphertext"], "secret_key": key["secret_key"]}
				if signed {
					data["pqc_public_key"] = setup["pqc_public_key"]
				}
				decoded := request(t, b, storage, "decrypt", data, false)
				if decoded["plaintext"] != plain {
					t.Fatal("plaintext mismatch")
				}
				data["secret_key"] = wrong["secret_key"]
				failure := request(t, b, storage, "decrypt", data, true)
				if !strings.Contains(failure["error"].(string), "-3") {
					t.Fatal("expected policy mismatch", failure)
				}
				if signed {
					// Tampering must fail signature verification through the same endpoint.
					raw, err := base64.StdEncoding.DecodeString(cipher["ciphertext"].(string))
					if err != nil {
						t.Fatal(err)
					}
					raw[len(raw)-1] ^= 1
					data["secret_key"] = key["secret_key"]
					data["ciphertext"] = base64.StdEncoding.EncodeToString(raw)
					request(t, b, storage, "decrypt", data, true)
				}
			})
		}
	}
}

func TestCovercryptANDOR(t *testing.T) {
	b, storage := newTestBackend(t)
	setup := request(t, b, storage, "setup", map[string]interface{}{"scheme": "covercrypt", "config_json": testConfig}, false)
	policies := []string{"Department::IT && Level::ADMIN", "Department::IT || Level::ADMIN"}
	grants := []string{"Department::IT Level::ADMIN", "Department::IT", "Level::ADMIN", "Department::HR"}
	for index, policy := range policies {
		cipher := request(t, b, storage, "encrypt", map[string]interface{}{"scheme": "covercrypt", "public_key": setup["public_key"], "plaintext": "aGVsbG8=", "policy": policy}, false)
		for user, attrs := range grants {
			key := request(t, b, storage, "genkey", map[string]interface{}{"scheme": "covercrypt", "attributes": attrs}, false)
			denied := (index == 0 && user != 0) || (index == 1 && user == 3)
			request(t, b, storage, "decrypt", map[string]interface{}{"ciphertext": cipher["ciphertext"], "secret_key": key["secret_key"]}, denied)
		}
	}
}

func TestValidationAndStoredScheme(t *testing.T) {
	b, storage := newTestBackend(t)
	request(t, b, storage, "setup", map[string]interface{}{"scheme": "unknown"}, true)
	request(t, b, storage, "genkey", map[string]interface{}{"scheme": "ac17", "attributes": "admin"}, true)
	request(t, b, storage, "setup", map[string]interface{}{"scheme": "ac17", "pqc": true}, false)
	request(t, b, storage, "genkey", map[string]interface{}{"scheme": "covercrypt", "attributes": "Department::IT"}, true)
	request(t, b, storage, "encrypt", map[string]interface{}{"public_key": "invalid!", "plaintext": "aGVsbG8=", "policy": "admin"}, true)
	request(t, b, storage, "decrypt", map[string]interface{}{"secret_key": "invalid!", "ciphertext": "aGVsbG8="}, true)
	request(t, b, storage, "setup", map[string]interface{}{"scheme": "ac17", "pqc": false}, false)
	state, err := loadAuthority(context.Background(), storage)
	if err != nil || len(state.PQCSecret) != 0 {
		t.Fatal("unsigned setup retained an obsolete signing key", err)
	}
}

func TestCovercryptJSONGrowthAndPersistence(t *testing.T) {
	// Deliberately unusable process settings must never affect JSON requests.
	t.Setenv("HCPABE_COVERCRYPT_CONFIG", "/does-not-exist.json")
	t.Setenv("HCPABE_COVERCRYPT_MODE", "invalid")
	for _, mode := range []string{"classic", "post_quantum", "hybridized"} {
		t.Run(mode, func(t *testing.T) {
			b, storage := newTestBackend(t)
			setup := request(t, b, storage, "setup", map[string]interface{}{"scheme": "covercrypt", "config_json": testConfig, "mode": mode, "pqc": true}, false)
			old := request(t, b, storage, "genkey", map[string]interface{}{"scheme": "covercrypt", "attributes": "Department::IT Level::ADMIN"}, false)
			plain := "aGVsbG8="
			before := request(t, b, storage, "encrypt", map[string]interface{}{"scheme": "covercrypt", "public_key": setup["public_key"], "plaintext": plain, "policy": "Department::IT && Level::ADMIN"}, false)
			grown := request(t, b, storage, "add_dimension", map[string]interface{}{"dimension_json": `{"name":"E","attributes":["present","absent"]}`}, false)
			if grown["pqc_public_key"] != setup["pqc_public_key"] || grown["mode"] != mode || grown["revision"] != uint64(2) {
				t.Fatal("growth changed signing keys/mode or lost revision")
			}
			var config struct {
				Dimensions []json.RawMessage `json:"dimensions"`
			}
			if err := json.Unmarshal([]byte(grown["config_json"].(string)), &config); err != nil || len(config.Dimensions) != 3 {
				t.Fatal("configuration not extended", err)
			}
			decrypt := func(key, cipher interface{}, denied bool) {
				response := request(t, b, storage, "decrypt", map[string]interface{}{"secret_key": key, "ciphertext": cipher, "pqc_public_key": setup["pqc_public_key"]}, denied)
				if !denied && response["plaintext"] != plain {
					t.Fatal("plaintext mismatch")
				}
			}
			decrypt(old["secret_key"], before["ciphertext"], false)
			after := request(t, b, storage, "encrypt", map[string]interface{}{"scheme": "covercrypt", "public_key": grown["public_key"], "plaintext": plain, "policy": "Department::IT && Level::ADMIN"}, false)
			decrypt(old["secret_key"], after["ciphertext"], false)
			after = request(t, b, storage, "encrypt", map[string]interface{}{"scheme": "covercrypt", "public_key": grown["public_key"], "plaintext": plain, "policy": "Department::IT && E::present"}, false)
			decrypt(old["secret_key"], after["ciphertext"], true)
			configBackend := logical.TestBackendConfig()
			configBackend.StorageView = storage
			reloaded, err := Factory(context.Background(), configBackend)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { reloaded.Cleanup(context.Background()) })
			newKey := request(t, reloaded, storage, "genkey", map[string]interface{}{"scheme": "covercrypt", "attributes": "Department::IT Level::ADMIN E::present"}, false)
			decrypt(newKey["secret_key"], after["ciphertext"], false)
			decrypt(newKey["secret_key"], before["ciphertext"], false)
			snapshot, _ := storage.Get(context.Background(), authorityKey)
			for _, bad := range []string{`{"name":"E","attributes":["other"]}`, `{`, `null`, `{"name":"F","attributes":[]}`} {
				request(t, b, storage, "add_dimension", map[string]interface{}{"dimension_json": bad}, true)
				unchanged, _ := storage.Get(context.Background(), authorityKey)
				if !bytes.Equal(snapshot.Value, unchanged.Value) {
					t.Fatal("failed growth modified authority")
				}
			}
		})
	}
}

type failingAuthorityStorage struct{ logical.Storage }

func (s failingAuthorityStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if entry.Key == authorityKey {
		return errors.New("injected storage write failure")
	}
	return s.Storage.Put(ctx, entry)
}

func TestJSONValidationAndAtomicStorage(t *testing.T) {
	b, storage := newTestBackend(t)
	request(t, b, storage, "add_dimension", map[string]interface{}{"dimension_json": `{"name":"E","attributes":["yes"]}`}, true)
	for _, params := range []map[string]interface{}{
		{"scheme": "covercrypt"}, {"scheme": "covercrypt", "config_json": "{"},
		{"scheme": "covercrypt", "config_json": testConfig, "mode": "invalid"},
		{"scheme": "covercrypt", "config_json": `{"dimensions":[]}`},
		{"scheme": "ac17", "config_json": testConfig},
	} {
		request(t, b, storage, "setup", params, true)
	}
	request(t, b, storage, "setup", map[string]interface{}{"scheme": "covercrypt", "config_json": testConfig}, false)
	before, _ := storage.Get(context.Background(), authorityKey)
	_, setupError := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "setup", Storage: failingAuthorityStorage{storage}, Data: map[string]interface{}{"scheme": "covercrypt", "config_json": testConfig}})
	if setupError == nil {
		t.Fatal("failed setup storage commit reported success")
	}
	unchanged, _ := storage.Get(context.Background(), authorityKey)
	if !bytes.Equal(before.Value, unchanged.Value) {
		t.Fatal("failed setup replaced the authority")
	}
	response, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "add_dimension", Storage: failingAuthorityStorage{storage}, Data: map[string]interface{}{"dimension_json": `{"name":"E","attributes":["yes"]}`}})
	if err == nil || response != nil {
		t.Fatal("failed storage write reported success")
	}
	after, _ := storage.Get(context.Background(), authorityKey)
	if !bytes.Equal(before.Value, after.Value) {
		t.Fatal("storage failure committed partial authority")
	}
	request(t, b, storage, "add_dimension", map[string]interface{}{"dimension_json": `{"name":"E","attributes":["yes"]}`}, false)
	request(t, b, storage, "setup", map[string]interface{}{"scheme": "ac17"}, false)
	request(t, b, storage, "add_dimension", map[string]interface{}{"dimension_json": `{"name":"F","attributes":["yes"]}`}, true)
}

func TestCovercryptMountIsolation(t *testing.T) {
	left, ls := newTestBackend(t)
	right, rs := newTestBackend(t)
	request(t, left, ls, "setup", map[string]interface{}{"scheme": "covercrypt", "config_json": testConfig, "mode": "classic"}, false)
	request(t, right, rs, "setup", map[string]interface{}{"scheme": "covercrypt", "config_json": `{"dimensions":[{"name":"X","attributes":["yes"]}]}`, "mode": "post_quantum"}, false)
	request(t, left, ls, "add_dimension", map[string]interface{}{"dimension_json": `{"name":"E","attributes":["yes"]}`}, false)
	request(t, right, rs, "genkey", map[string]interface{}{"scheme": "covercrypt", "attributes": "X::yes"}, false)
	request(t, right, rs, "genkey", map[string]interface{}{"scheme": "covercrypt", "attributes": "E::yes"}, true)
	l, _ := loadAuthority(context.Background(), ls)
	r, _ := loadAuthority(context.Background(), rs)
	if l.Mode != "classic" || r.Mode != "post_quantum" || bytes.Contains(r.Config, []byte(`"E"`)) {
		t.Fatal("mount state leaked")
	}
}

func TestLegacyAuthorityReadCompatibility(t *testing.T) {
	b, storage := newTestBackend(t)
	setup := request(t, b, storage, "setup", map[string]interface{}{"scheme": "ac17", "pqc": true}, false)
	state, err := loadAuthority(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(context.Background(), &logical.StorageEntry{Key: "msk/abe", Value: state.MSK}); err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(context.Background(), &logical.StorageEntry{Key: "msk/pqc", Value: state.PQCSecret}); err != nil {
		t.Fatal(err)
	}
	config, err := logical.StorageEntryJSON("config/abe", map[string]interface{}{"scheme": "ac17"})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if err := storage.Delete(context.Background(), authorityKey); err != nil {
		t.Fatal(err)
	}
	key := request(t, b, storage, "genkey", map[string]interface{}{"scheme": "ac17", "attributes": "admin"}, false)
	cipher := request(t, b, storage, "encrypt", map[string]interface{}{"scheme": "ac17", "public_key": setup["public_key"], "plaintext": "aGVsbG8=", "policy": "admin"}, false)
	result := request(t, b, storage, "decrypt", map[string]interface{}{"secret_key": key["secret_key"], "ciphertext": cipher["ciphertext"], "pqc_public_key": setup["pqc_public_key"]}, false)
	if result["plaintext"] != "aGVsbG8=" {
		t.Fatal("legacy key compatibility failed")
	}
}
