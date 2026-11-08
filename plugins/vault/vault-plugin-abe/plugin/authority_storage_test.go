package abe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// Model the backend entry limit at the production Storage.Put boundary.
type boundedAuthorityStorage struct {
	logical.Storage
	limit int
}

func largeFixtureAuthority() *authorityState {
	return &authorityState{Format: 1, Revision: 9, Scheme: "covercrypt",
		MSK: bytes.Repeat([]byte{1}, 1<<20), PK: bytes.Repeat([]byte{2}, 1<<19),
		PQCSecret: []byte("synthetic-signing-secret"), PQCPublic: []byte("synthetic-verifier"),
		Config: json.RawMessage(testConfig), Mode: "hybridized"}
}

type interruptedAuthorityStorage struct {
	logical.Storage
	failKey         string
	commitThenError bool
}

func (s interruptedAuthorityStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if entry.Key == s.failKey || (s.failKey == "chunk" && strings.HasSuffix(entry.Key, "/000001")) {
		if s.commitThenError {
			if err := s.Storage.Put(ctx, entry); err != nil {
				return err
			}
		}
		return errors.New("injected storage timeout")
	}
	return s.Storage.Put(ctx, entry)
}

func TestChunkCommitInterruption(t *testing.T) {
	for _, failure := range []struct {
		key       string
		committed bool
	}{{"chunk", false}, {authorityKey, false}, {authorityKey, true}} {
		t.Run(fmt.Sprintf("%s/committed=%v", failure.key, failure.committed), func(t *testing.T) {
			ctx := context.Background()
			storage := &logical.InmemStorage{}
			old := &authorityState{Format: 1, Revision: 1, Scheme: "ac17", MSK: []byte("old-synthetic-master"), PK: []byte("old-public")}
			if err := saveAuthority(ctx, storage, old); err != nil {
				t.Fatal(err)
			}
			next := largeFixtureAuthority()
			if err := saveAuthority(ctx, interruptedAuthorityStorage{storage, failure.key, failure.committed}, next); err == nil {
				t.Fatal("injected write failure reported success")
			}
			actual, err := loadAuthority(ctx, storage)
			if err != nil {
				t.Fatal(err)
			}
			expected := old
			if failure.committed {
				expected = next
			}
			if !reflect.DeepEqual(actual, expected) {
				t.Fatal("commit interruption lost/mixed authority state")
			}
		})
	}
}

func TestChunkCorruptionFailsClosed(t *testing.T) {
	for _, mutation := range []string{"missing", "short", "checksum", "generation", "digest", "count", "size", "format", "chunk_size", "revision"} {
		t.Run(mutation, func(t *testing.T) {
			ctx := context.Background()
			storage := &logical.InmemStorage{}
			if err := saveAuthority(ctx, storage, largeFixtureAuthority()); err != nil {
				t.Fatal(err)
			}
			// Corrupt primary state must never fall back to obsolete master keys.
			storage.Put(ctx, &logical.StorageEntry{Key: "msk/abe", Value: []byte("obsolete-synthetic-master")})
			entry, _ := storage.Get(ctx, authorityKey)
			var manifest authorityChunkManifest
			if err := entry.DecodeJSON(&manifest); err != nil {
				t.Fatal(err)
			}
			key := authorityChunkKey(manifest.Generation, 0)
			switch mutation {
			case "missing":
				storage.Delete(ctx, key)
			case "short", "checksum":
				chunk, _ := storage.Get(ctx, key)
				if mutation == "short" {
					chunk.Value = chunk.Value[:len(chunk.Value)-1]
				} else {
					chunk.Value[0] ^= 1
				}
				storage.Put(ctx, chunk)
			case "generation":
				manifest.Generation = "../escape"
			case "digest":
				manifest.PayloadSHA256 = strings.Repeat("z", 64)
			case "count":
				manifest.ChunkCount++
			case "size":
				manifest.PayloadSize = maxAuthorityPayloadSize + 1
			case "format":
				manifest.Format = 99
			case "chunk_size":
				manifest.ChunkSize++
			case "revision":
				manifest.Revision++
			}
			entry, _ = logical.StorageEntryJSON(authorityKey, manifest)
			if err := storage.Put(ctx, entry); err != nil {
				t.Fatal(err)
			}
			if state, err := loadAuthority(ctx, storage); err == nil || state != nil {
				t.Fatal("corrupt authority was accepted")
			}
		})
	}
}

// Independently encode the exact retired CPQA manifest layout. Reading does
// not rewrite it; a future successful authority update can write format 3.
func storeRetiredChunkFixture(t *testing.T, storage logical.Storage, state *authorityState) {
	t.Helper()
	ctx := context.Background()
	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	generation := strings.Repeat("a", 32)
	count := (len(payload) + legacyAuthorityChunkSize - 1) / legacyAuthorityChunkSize
	for i := 0; i < count; i++ {
		end := (i + 1) * legacyAuthorityChunkSize
		if end > len(payload) {
			end = len(payload)
		}
		if err := storage.Put(ctx, &logical.StorageEntry{Key: authorityChunkKey(generation, i), Value: payload[i*legacyAuthorityChunkSize : end]}); err != nil {
			t.Fatal(err)
		}
	}
	entry, err := logical.StorageEntryJSON(authorityKey, map[string]interface{}{
		"format": 2, "revision": state.Revision, "generation": generation, "chunk_count": count,
		"payload_size": len(payload), "payload_sha256": hex.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}
}

func TestRetiredChunkFormatReadAndSnapshotRetention(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	state := largeFixtureAuthority()
	storeRetiredChunkFixture(t, storage, state)
	before, _ := storage.Get(ctx, authorityKey)
	reloaded, err := loadAuthority(ctx, storage)
	if err != nil || !reflect.DeepEqual(reloaded, state) {
		t.Fatal("retired format read failed", err)
	}
	after, _ := storage.Get(ctx, authorityKey)
	if !bytes.Equal(before.Value, after.Value) {
		t.Fatal("read rewrote retired authority")
	}
	state.Revision++
	if err := saveAuthority(ctx, boundedAuthorityStorage{storage, 256 * 1024}, state); err != nil {
		t.Fatal(err)
	}
	var previous authorityChunkManifest
	before.DecodeJSON(&previous)
	if _, err := loadChunkedAuthority(ctx, storage, previous); err != nil {
		t.Fatal("old snapshot lost after commit", err)
	}
	current, _ := storage.Get(ctx, authorityKey)
	var next authorityChunkManifest
	current.DecodeJSON(&next)
	if next.Format != 3 {
		t.Fatal("new write did not use format 3")
	}
}

func (s boundedAuthorityStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if len(entry.Value) > s.limit {
		return fmt.Errorf("storage entry exceeds %d-byte limit", s.limit)
	}
	return s.Storage.Put(ctx, entry)
}

func TestAuthorityExceedsRaftEntryLimit(t *testing.T) {
	ctx := context.Background()
	storage := boundedAuthorityStorage{&logical.InmemStorage{}, 1 << 20}
	state := &authorityState{Format: 1, Revision: 7, Scheme: "covercrypt",
		MSK: bytes.Repeat([]byte{1}, 1<<20), PK: bytes.Repeat([]byte{2}, 1<<19)}
	if err := saveAuthority(ctx, storage, state); err != nil {
		t.Fatal(err)
	}
	reloaded, err := loadAuthority(ctx, storage)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Revision != state.Revision || !bytes.Equal(reloaded.MSK, state.MSK) || !bytes.Equal(reloaded.PK, state.PK) {
		t.Fatal("authority did not survive the bounded-storage round trip")
	}
}
