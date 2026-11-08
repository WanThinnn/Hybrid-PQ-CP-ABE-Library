package abe

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
)

const authorityKey = "msk/authority"
const authorityChunkSize = 192 * 1024
const legacyAuthorityChunkSize = 768 * 1024
const maxAuthorityPayloadSize = 1 << 30
const inlinePublicKeySize = 256 * 1024
const publicKeyReferencePrefix = "vault-authority-sha256:"

// Small authorities use format 1. Large authorities use immutable chunks and
// a format-3 manifest committed last under the same seal-wrapped msk/ prefix.
type authorityState struct {
	Format    int             `json:"format"`
	Revision  uint64          `json:"revision"`
	Scheme    string          `json:"scheme"`
	MSK       []byte          `json:"msk"`
	PK        []byte          `json:"pk"`
	PQCSecret []byte          `json:"pqc_secret,omitempty"`
	PQCPublic []byte          `json:"pqc_public,omitempty"`
	Config    json.RawMessage `json:"config,omitempty"`
	Mode      string          `json:"mode,omitempty"`
}

type authorityChunkManifest struct {
	Format        int    `json:"format"`
	Revision      uint64 `json:"revision"`
	Generation    string `json:"generation"`
	ChunkSize     int    `json:"chunk_size,omitempty"`
	ChunkCount    int    `json:"chunk_count"`
	PayloadSize   int64  `json:"payload_size"`
	PayloadSHA256 string `json:"payload_sha256"`
}

func authorityChunkKey(generation string, index int) string {
	return fmt.Sprintf("%s/chunks/%s/%06d", authorityKey, generation, index)
}

func loadChunkedAuthority(ctx context.Context, storage logical.Storage, manifest authorityChunkManifest) (*authorityState, error) {
	chunkSize := manifest.ChunkSize
	// Read-only compatibility with CPQA's retired format-2 chunk writer.
	if manifest.Format == 2 && chunkSize == 0 {
		chunkSize = legacyAuthorityChunkSize
	} else if manifest.Format != 3 || chunkSize != authorityChunkSize {
		return nil, fmt.Errorf("unsupported authority chunk format")
	}
	generation, err := hex.DecodeString(manifest.Generation)
	if err != nil || len(generation) != 16 || hex.EncodeToString(generation) != manifest.Generation ||
		manifest.PayloadSize <= 0 || manifest.PayloadSize > maxAuthorityPayloadSize {
		return nil, fmt.Errorf("invalid authority chunk manifest")
	}
	digest, err := hex.DecodeString(manifest.PayloadSHA256)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != manifest.PayloadSHA256 ||
		manifest.ChunkCount != int((manifest.PayloadSize+int64(chunkSize)-1)/int64(chunkSize)) {
		return nil, fmt.Errorf("invalid authority chunk manifest")
	}
	payload := make([]byte, 0, int(manifest.PayloadSize))
	for index := 0; index < manifest.ChunkCount; index++ {
		chunk, err := storage.Get(ctx, authorityChunkKey(manifest.Generation, index))
		if err != nil {
			return nil, err
		}
		expected := chunkSize
		if remaining := int(manifest.PayloadSize) - len(payload); remaining < expected {
			expected = remaining
		}
		if chunk == nil || len(chunk.Value) != expected {
			return nil, fmt.Errorf("missing or invalid authority chunk %d", index)
		}
		payload = append(payload, chunk.Value...)
	}
	checksum := sha256.Sum256(payload)
	if hex.EncodeToString(checksum[:]) != manifest.PayloadSHA256 {
		return nil, fmt.Errorf("authority chunk checksum mismatch")
	}
	var state authorityState
	if err := json.Unmarshal(payload, &state); err != nil {
		return nil, fmt.Errorf("invalid authority payload")
	}
	if state.Format != 1 || len(state.MSK) == 0 || state.Revision != manifest.Revision {
		return nil, fmt.Errorf("invalid authority payload")
	}
	return &state, nil
}

func loadAuthority(ctx context.Context, storage logical.Storage) (*authorityState, error) {
	entry, err := storage.Get(ctx, authorityKey)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		var manifest authorityChunkManifest
		if err := json.Unmarshal(entry.Value, &manifest); err != nil {
			return nil, fmt.Errorf("invalid authority record")
		}
		if manifest.Format == 2 || manifest.Format == 3 {
			return loadChunkedAuthority(ctx, storage, manifest)
		}
		var state authorityState
		if err := entry.DecodeJSON(&state); err != nil {
			return nil, fmt.Errorf("invalid authority record")
		}
		if state.Format != 1 || len(state.MSK) == 0 {
			return nil, fmt.Errorf("invalid stored authority")
		}
		return &state, nil
	}
	// Read old installations without replacing, re-issuing or migrating keys.
	master, err := storage.Get(ctx, "msk/abe")
	if err != nil || master == nil {
		return nil, err
	}
	state := &authorityState{MSK: master.Value}
	config, err := storage.Get(ctx, "config/abe")
	if err != nil {
		return nil, err
	}
	if config != nil {
		if err := config.DecodeJSON(state); err != nil {
			return nil, err
		}
	}
	signing, err := storage.Get(ctx, "msk/pqc")
	if err != nil {
		return nil, err
	}
	if signing != nil {
		state.PQCSecret = signing.Value
	}
	return state, nil
}

func saveAuthority(ctx context.Context, storage logical.Storage, state *authorityState) error {
	if state == nil || state.Format != 1 || len(state.MSK) == 0 {
		return fmt.Errorf("invalid authority state")
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(payload) <= authorityChunkSize {
		return storage.Put(ctx, &logical.StorageEntry{Key: authorityKey, Value: payload})
	}
	if len(payload) > maxAuthorityPayloadSize {
		return fmt.Errorf("authority exceeds the 1 GiB serialized payload budget")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	manifest := authorityChunkManifest{
		Format: 3, Revision: state.Revision, Generation: hex.EncodeToString(nonce[:]),
		ChunkSize: authorityChunkSize, PayloadSize: int64(len(payload)),
		ChunkCount: (len(payload) + authorityChunkSize - 1) / authorityChunkSize,
	}
	checksum := sha256.Sum256(payload)
	manifest.PayloadSHA256 = hex.EncodeToString(checksum[:])
	for index := 0; index < manifest.ChunkCount; index++ {
		start, end := index*authorityChunkSize, (index+1)*authorityChunkSize
		if end > len(payload) {
			end = len(payload)
		}
		if err := storage.Put(ctx, &logical.StorageEntry{
			Key: authorityChunkKey(manifest.Generation, index), Value: payload[start:end],
		}); err != nil {
			return err
		}
	}
	entry, err := logical.StorageEntryJSON(authorityKey, manifest)
	if err != nil {
		return err
	}
	// Never delete chunks after a commit error: a timed-out Put may have committed.
	// Retain old/orphan generations for snapshot readers and operator recovery.
	return storage.Put(ctx, entry)
}

func (state *authorityState) publicKeyFingerprint() string {
	digest := sha256.Sum256(state.PK)
	return hex.EncodeToString(digest[:])
}

func (state *authorityState) publicKeyReference() string {
	return publicKeyReferencePrefix + state.publicKeyFingerprint()
}

func validPublicKeyFormat(value string) bool {
	return value == "auto" || value == "base64" || value == "reference"
}

func (state *authorityState) publicResponseWithFormat(format string) *logical.Response {
	publicKey, encoding := "", "base64"
	if len(state.PK) != 0 {
		if format == "reference" || (format == "auto" && len(state.PK) > inlinePublicKeySize) {
			publicKey, encoding = state.publicKeyReference(), "vault-authority-sha256-v1"
		} else {
			publicKey = base64.StdEncoding.EncodeToString(state.PK)
		}
	}
	data := map[string]interface{}{
		"public_key": publicKey, "public_key_format": encoding, "scheme": state.Scheme,
		"contract_version": 1,
		"pqc":              len(state.PQCSecret) != 0, "native_version": nativeVersion(), "revision": state.Revision,
	}
	if len(state.PK) != 0 {
		data["public_key_fingerprint"] = state.publicKeyFingerprint()
	}
	if len(state.PQCPublic) != 0 {
		data["pqc_public_key"] = base64.StdEncoding.EncodeToString(state.PQCPublic)
	}
	if len(state.Config) != 0 {
		data["config_json"] = string(state.Config)
		data["mode"] = state.Mode
	}
	return &logical.Response{Data: data}
}

func (state *authorityState) publicResponse() *logical.Response {
	return state.publicResponseWithFormat("auto")
}
