package abe

/*
#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"unsafe"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathAddDimension(b *abeBackend) *framework.Path {
	return &framework.Path{
		Pattern: "add_dimension",
		Fields: map[string]*framework.FieldSchema{
			"dimension_json": {Type: framework.TypeString, Required: true,
				Description: "One Covercrypt dimension JSON object; CLI: dimension_json=@file.json"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathAddDimensionWrite},
		},
		HelpSynopsis:    "Add a dimension to the stored Covercrypt authority without a new setup.",
		HelpDescription: "Retains existing user rights and signing keys. Returns the updated public key; issue authorized user keys to grant the new dimension. MSK and configuration are updated together.",
	}
}

func (b *abeBackend) pathAddDimensionWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.authorityMu.Lock()
	defer b.authorityMu.Unlock()
	state, err := loadAuthority(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return logical.ErrorResponse("Authority not found; run setup first"), nil
	}
	if state.Scheme != "covercrypt" {
		return logical.ErrorResponse("add_dimension requires a Covercrypt authority"), nil
	}
	if state.Format != 1 || len(state.Config) == 0 {
		return logical.ErrorResponse("This legacy authority has no stored JSON/mode; growth through this endpoint requires a JSON-configured authority. Existing keys remain usable."), nil
	}
	dimension := data.Get("dimension_json").(string)
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(dimension), &object); err != nil || object == nil {
		return logical.ErrorResponse("dimension_json must be one JSON object with name and attributes"), nil
	}
	var config struct {
		Dimensions []json.RawMessage `json:"dimensions"`
	}
	if err := json.Unmarshal(state.Config, &config); err != nil {
		return nil, err
	}
	config.Dimensions = append(config.Dimensions, json.RawMessage(dimension))
	updatedJSON, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	mode, err := covercryptMode(state.Mode)
	if err != nil {
		return nil, err
	}
	master := (*C.uchar)(C.CBytes(state.MSK))
	defer C.free(unsafe.Pointer(master))
	cJSON := C.CString(dimension)
	defer FreeCString(cJSON)
	var pk, msk *C.uchar
	var pkLen, mskLen C.size_t
	defer func() { FreeCBytes(pk); FreeCBytes(msk) }()
	status := C.hybrid_cpabe_covercrypt_add_dimensionBuffer_with_mode(master, C.size_t(len(state.MSK)), cJSON,
		mode, &pk, &pkLen, &msk, &mskLen)
	if status != C.HCPABE_SUCCESS {
		return logical.ErrorResponse(nativeError("add_dimension", status).Error()), nil
	}
	next := *state
	next.Revision++
	next.PK = C.GoBytes(unsafe.Pointer(pk), C.int(pkLen))
	next.MSK = C.GoBytes(unsafe.Pointer(msk), C.int(mskLen))
	next.Config = updatedJSON
	if err := saveAuthority(ctx, req.Storage, &next); err != nil {
		return nil, err
	}
	return next.publicResponse(), nil
}
