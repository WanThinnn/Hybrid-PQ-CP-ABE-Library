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

func pathSetup(b *abeBackend) *framework.Path {
	return &framework.Path{
		Pattern: "setup",
		Fields: map[string]*framework.FieldSchema{
			"scheme": {
				Type:        framework.TypeString,
				Description: "ABE Scheme (ac17 or tkn20)",
				Default:     "ac17",
			},
			"pqc": {
				Type:        framework.TypeBool,
				Description: "Enable Post-Quantum Cryptography (ML-DSA) signatures",
				Default:     false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSetupWrite,
			},
		},
		HelpSynopsis:    "Sets up the ABE scheme and generates Master Secret Key (MSK) and Public Key (PK).",
		HelpDescription: "The MSK is securely stored in Vault. The PK is returned to the client.",
	}
}

func (b *abeBackend) pathSetupWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	schemeStr := data.Get("scheme").(string)
	usePqc := data.Get("pqc").(bool)

	var cScheme C.CPABEScheme
	if schemeStr == "tkn20" {
		cScheme = C.CPABE_SCHEME_TKN20
	} else if schemeStr == "ac17" {
		cScheme = C.CPABE_SCHEME_AC17
	} else {
		return logical.ErrorResponse("unsupported scheme. Use 'ac17' or 'tkn20'"), nil
	}

	var pkBuffer *C.uchar
	var pkLen C.size_t
	var mskBuffer *C.uchar
	var mskLen C.size_t

	var pqcPkBuffer *C.uchar
	var pqcPkLen C.size_t
	var pqcMskBuffer *C.uchar
	var pqcMskLen C.size_t

	var res C.int

	if usePqc {
		res = C.hybrid_cpabe_setupBuffer_with_pqc_scheme(
			&pkBuffer, &pkLen,
			&mskBuffer, &mskLen,
			&pqcPkBuffer, &pqcPkLen,
			&pqcMskBuffer, &pqcMskLen,
			cScheme)
	} else {
		res = C.hybrid_cpabe_setupBuffer_with_scheme(
			&pkBuffer, &pkLen,
			&mskBuffer, &mskLen,
			cScheme)
	}

	if res != C.HCPABE_SUCCESS {
		return nil, errors.New("failed to generate ABE setup keys")
	}

	// Defer freeing C memory
	defer func() {
		if pkBuffer != nil {
			FreeCBytes(pkBuffer)
		}
		if mskBuffer != nil {
			FreeCBytes(mskBuffer)
		}
		if pqcPkBuffer != nil {
			FreeCBytes(pqcPkBuffer)
		}
		if pqcMskBuffer != nil {
			FreeCBytes(pqcMskBuffer)
		}
	}()

	pkBytes := C.GoBytes(unsafe.Pointer(pkBuffer), C.int(pkLen))
	mskBytes := C.GoBytes(unsafe.Pointer(mskBuffer), C.int(mskLen))

	var pqcPkBytes []byte
	var pqcMskBytes []byte
	if usePqc {
		pqcPkBytes = C.GoBytes(unsafe.Pointer(pqcPkBuffer), C.int(pqcPkLen))
		pqcMskBytes = C.GoBytes(unsafe.Pointer(pqcMskBuffer), C.int(pqcMskLen))
	}

	// Store MSK in Vault
	storageEntry := &logical.StorageEntry{
		Key:   "msk/abe",
		Value: mskBytes,
	}
	if err := req.Storage.Put(ctx, storageEntry); err != nil {
		return nil, err
	}

	if usePqc {
		pqcStorageEntry := &logical.StorageEntry{
			Key:   "msk/pqc",
			Value: pqcMskBytes,
		}
		if err := req.Storage.Put(ctx, pqcStorageEntry); err != nil {
			return nil, err
		}
	}

	respData := map[string]interface{}{
		"public_key": base64.StdEncoding.EncodeToString(pkBytes),
		"scheme":     schemeStr,
		"pqc":        usePqc,
	}
	
	if usePqc {
		respData["pqc_public_key"] = base64.StdEncoding.EncodeToString(pqcPkBytes)
	}

	return &logical.Response{
		Data: respData,
	}, nil
}
