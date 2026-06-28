package abe

/*
#cgo CFLAGS: -I../../../cpp/include
#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/base64"
	"errors"
	"unsafe"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathGenKey(b *abeBackend) *framework.Path {
	return &framework.Path{
		Pattern: "genkey",
		Fields: map[string]*framework.FieldSchema{
			"attributes": {
				Type:        framework.TypeString,
				Description: "Attributes for the generated key (e.g., 'admin it hr')",
				Required:    true,
			},
			"scheme": {
				Type:        framework.TypeString,
				Description: "ABE Scheme (ac17 or tkn20)",
				Default:     "ac17",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathGenKeyWrite,
			},
		},
		HelpSynopsis:    "Generates a new CP-ABE secret key for the given attributes.",
		HelpDescription: "Reads the Master Secret Key from internal storage and computes a user secret key.",
	}
}

func (b *abeBackend) pathGenKeyWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	attributes := data.Get("attributes").(string)
	schemeStr := data.Get("scheme").(string)

	if attributes == "" {
		return logical.ErrorResponse("attributes are required"), nil
	}

	var cScheme C.CPABEScheme
	if schemeStr == "tkn20" {
		cScheme = C.CPABE_SCHEME_TKN20
	} else if schemeStr == "ac17" {
		cScheme = C.CPABE_SCHEME_AC17
	} else {
		return logical.ErrorResponse("unsupported scheme. Use 'ac17' or 'tkn20'"), nil
	}

	// Read MSK from storage
	storageEntry, err := req.Storage.Get(ctx, "msk/abe")
	if err != nil {
		return nil, err
	}
	if storageEntry == nil || len(storageEntry.Value) == 0 {
		return logical.ErrorResponse("MSK not found. Please run setup first."), nil
	}

	mskBytes := storageEntry.Value
	mskBuffer := (*C.uchar)(C.CBytes(mskBytes))
	defer C.free(unsafe.Pointer(mskBuffer))

	cAttributes := C.CString(attributes)
	defer FreeCString(cAttributes)

	var skBuffer *C.uchar
	var skLen C.size_t

	res := C.hybrid_cpabe_genkeyBuffer_with_scheme(
		mskBuffer, C.size_t(len(mskBytes)),
		cAttributes,
		&skBuffer, &skLen,
		cScheme)

	if res != C.HCPABE_SUCCESS {
		return nil, errors.New("failed to generate ABE secret key")
	}

	defer FreeCBytes(skBuffer)

	skBytes := C.GoBytes(unsafe.Pointer(skBuffer), C.int(skLen))

	return &logical.Response{
		Data: map[string]interface{}{
			"secret_key": base64.StdEncoding.EncodeToString(skBytes),
			"attributes": attributes,
			"scheme":     schemeStr,
		},
	}, nil
}
