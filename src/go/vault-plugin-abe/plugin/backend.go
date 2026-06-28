package abe

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// abeBackend defines the object for our backend
type abeBackend struct {
	*framework.Backend
}

// Factory creates a new backend instance
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// backend defines the logical paths for this plugin
func backend() *abeBackend {
	var b abeBackend

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
				"msk",
			},
		},
		Paths: []*framework.Path{
			pathSetup(&b),
			pathGenKey(&b),
			pathEncrypt(&b),
			pathDecrypt(&b),
		},
		BackendType: logical.TypeLogical,
	}

	return &b
}

const backendHelp = `
The Hybrid PQ CP-ABE backend provides an engine for generating and managing
Attribute-Based Encryption keys, as well as providing endpoints to encrypt and decrypt
data using the ABE policy language.
`
