package abe

/*
#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"unsafe"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathSetup(b *abeBackend) *framework.Path {
	return &framework.Path{
		Pattern: "setup",
		Fields: map[string]*framework.FieldSchema{
			"scheme":      {Type: framework.TypeString, Description: "ac17, tkn20 or covercrypt", Default: "ac17"},
			"pqc":         {Type: framework.TypeBool, Description: "Enable ML-DSA signatures", Default: false},
			"config_json": {Type: framework.TypeString, Description: "Covercrypt JSON text containing a dimensions array; CLI: config_json=@file.json"},
			"mode":        {Type: framework.TypeString, Description: "Covercrypt mode: classic, post_quantum or hybridized", Default: "hybridized"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathSetupWrite},
		},
		HelpSynopsis:    "Create an ABE authority; Covercrypt takes config_json directly.",
		HelpDescription: "Replaces the mount's authority. Secrets and configuration are stored together. To extend Covercrypt without replacing keys use add_dimension.",
	}
}

func (b *abeBackend) pathSetupWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.authorityMu.Lock()
	defer b.authorityMu.Unlock()
	scheme := data.Get("scheme").(string)
	signed := data.Get("pqc").(bool)
	cScheme, err := nativeScheme(scheme)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	config := strings.TrimSpace(data.Get("config_json").(string))
	mode := data.Get("mode").(string)
	if scheme == "covercrypt" {
		if config == "" || !json.Valid([]byte(config)) {
			return logical.ErrorResponse("Covercrypt requires valid config_json text with a dimensions array"), nil
		}
	} else if config != "" {
		return logical.ErrorResponse("config_json is only supported for covercrypt"), nil
	}
	var pk, msk, pqcPK, pqcSK *C.uchar
	var pkLen, mskLen, pqcPKLen, pqcSKLen C.size_t
	defer func() { FreeCBytes(pk); FreeCBytes(msk); FreeCBytes(pqcPK); FreeCBytes(pqcSK) }()
	var status C.int
	if scheme == "covercrypt" {
		cMode, err := covercryptMode(mode)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
		cJSON := C.CString(config)
		defer FreeCString(cJSON)
		status = C.hybrid_cpabe_covercrypt_setupBuffer_from_json(cJSON, cMode, &pk, &pkLen, &msk, &mskLen)
		if status == C.HCPABE_SUCCESS && signed {
			status = C.ml_dsa_87_generate_keypair(&pqcPK, &pqcPKLen, &pqcSK, &pqcSKLen)
			// The raw keypair API frees its buffers internally on failure.
			if status != C.HCPABE_SUCCESS {
				pqcPK = nil
				pqcSK = nil
			}
		}
	} else if signed {
		status = C.hybrid_cpabe_setupBuffer_with_pqc_scheme(&pk, &pkLen, &msk, &mskLen,
			&pqcPK, &pqcPKLen, &pqcSK, &pqcSKLen, cScheme)
	} else {
		status = C.hybrid_cpabe_setupBuffer_with_scheme(&pk, &pkLen, &msk, &mskLen, cScheme)
	}
	if status != C.HCPABE_SUCCESS {
		return logical.ErrorResponse(nativeError("setup", status).Error()), nil
	}
	state := &authorityState{
		Format: 1, Revision: 1, Scheme: scheme,
		PK: C.GoBytes(unsafe.Pointer(pk), C.int(pkLen)), MSK: C.GoBytes(unsafe.Pointer(msk), C.int(mskLen)),
	}
	if signed {
		state.PQCPublic = C.GoBytes(unsafe.Pointer(pqcPK), C.int(pqcPKLen))
		state.PQCSecret = C.GoBytes(unsafe.Pointer(pqcSK), C.int(pqcSKLen))
		if scheme == "covercrypt" {
			// The hybrid signing API consumes Base64 text, matching the existing
			// generic setup-with-PQC API rather than the raw ML-DSA keypair API.
			state.PQCPublic = []byte(base64.StdEncoding.EncodeToString(state.PQCPublic))
			state.PQCSecret = []byte(base64.StdEncoding.EncodeToString(state.PQCSecret))
		}
	}
	if scheme == "covercrypt" {
		state.Config = json.RawMessage(config)
		state.Mode = mode
	}
	if err := saveAuthority(ctx, req.Storage, state); err != nil {
		return nil, err
	}
	return state.publicResponse(), nil
}
