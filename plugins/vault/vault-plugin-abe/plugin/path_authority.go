package abe

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathAuthority(b *abeBackend) *framework.Path {
	return &framework.Path{
		Pattern: "authority",
		Fields: map[string]*framework.FieldSchema{
			"public_key_format": {Type: framework.TypeString, Default: "auto",
				Description: "Public key transport: auto, base64 or reference"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.pathAuthorityRead},
		},
		HelpSynopsis: "Read public authority metadata without creating, replacing or migrating keys.",
	}
}

func (b *abeBackend) pathAuthorityRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.authorityMu.RLock()
	defer b.authorityMu.RUnlock()
	format := data.Get("public_key_format").(string)
	if !validPublicKeyFormat(format) {
		return logical.ErrorResponse("public_key_format must be auto, base64 or reference"), nil
	}
	state, err := loadAuthority(ctx, req.Storage)
	if err != nil || state == nil {
		return nil, err
	}
	return state.publicResponseWithFormat(format), nil
}
