package abe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
)

const authorityKey = "msk/authority"

// One storage record commits the matching MSK, PK, signing keys and JSON
// together. It is covered by the backend's msk/ seal-wrap prefix.
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

func loadAuthority(ctx context.Context, storage logical.Storage) (*authorityState, error) {
	entry, err := storage.Get(ctx, authorityKey)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		var state authorityState
		if err := entry.DecodeJSON(&state); err != nil {
			return nil, err
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
	entry, err := logical.StorageEntryJSON(authorityKey, state)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

func (state *authorityState) publicResponse() *logical.Response {
	data := map[string]interface{}{
		"public_key": base64.StdEncoding.EncodeToString(state.PK), "scheme": state.Scheme,
		"pqc": len(state.PQCSecret) != 0, "native_version": nativeVersion(), "revision": state.Revision,
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
