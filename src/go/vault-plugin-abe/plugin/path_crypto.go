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

func pathEncrypt(b *abeBackend) *framework.Path {
	return &framework.Path{
		Pattern: "encrypt",
		Fields: map[string]*framework.FieldSchema{
			"plaintext": {
				Type:        framework.TypeString,
				Description: "Base64 encoded plaintext to encrypt (e.g. DEK)",
				Required:    true,
			},
			"policy": {
				Type:        framework.TypeString,
				Description: "Access policy (e.g. 'admin and it')",
				Required:    true,
			},
			"public_key": {
				Type:        framework.TypeString,
				Description: "Base64 encoded ABE Public Key",
				Required:    true,
			},
			"scheme": {
				Type:        framework.TypeString,
				Description: "ABE Scheme (ac17 or tkn20)",
				Default:     "ac17",
			},
			"pqc_private_key": {
				Type:        framework.TypeString,
				Description: "Base64 encoded PQC ML-DSA Secret Key for signing (optional)",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathEncryptWrite,
			},
		},
		HelpSynopsis:    "Encrypts data using an ABE policy.",
		HelpDescription: "Optionally signs the ciphertext if a PQC private key is provided.",
	}
}

func pathDecrypt(b *abeBackend) *framework.Path {
	return &framework.Path{
		Pattern: "decrypt",
		Fields: map[string]*framework.FieldSchema{
			"ciphertext": {
				Type:        framework.TypeString,
				Description: "Base64 encoded ciphertext",
				Required:    true,
			},
			"secret_key": {
				Type:        framework.TypeString,
				Description: "Base64 encoded user secret key",
				Required:    true,
			},
			"pqc_public_key": {
				Type:        framework.TypeString,
				Description: "Base64 encoded PQC ML-DSA Public Key for verification (optional)",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathDecryptWrite,
			},
		},
		HelpSynopsis:    "Decrypts ABE ciphertext.",
		HelpDescription: "Optionally verifies the signature if a PQC public key is provided.",
	}
}

func (b *abeBackend) pathEncryptWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	ptBase64 := data.Get("plaintext").(string)
	policy := data.Get("policy").(string)
	pkBase64 := data.Get("public_key").(string)
	schemeStr := data.Get("scheme").(string)
	pqcSkBase64 := data.Get("pqc_private_key").(string)

	if ptBase64 == "" || policy == "" || pkBase64 == "" {
		return logical.ErrorResponse("plaintext, policy, and public_key are required"), nil
	}

	var cScheme C.CPABEScheme
	if schemeStr == "tkn20" {
		cScheme = C.CPABE_SCHEME_TKN20
	} else if schemeStr == "ac17" {
		cScheme = C.CPABE_SCHEME_AC17
	} else {
		return logical.ErrorResponse("unsupported scheme. Use 'ac17' or 'tkn20'"), nil
	}

	ptBytes, err := base64.StdEncoding.DecodeString(ptBase64)
	if err != nil {
		return logical.ErrorResponse("plaintext must be base64 encoded"), nil
	}
	pkBytes, err := base64.StdEncoding.DecodeString(pkBase64)
	if err != nil {
		return logical.ErrorResponse("public_key must be base64 encoded"), nil
	}

	cPt := (*C.uchar)(C.CBytes(ptBytes))
	defer C.free(unsafe.Pointer(cPt))

	cPk := (*C.uchar)(C.CBytes(pkBytes))
	defer C.free(unsafe.Pointer(cPk))

	cPolicy := C.CString(policy)
	defer FreeCString(cPolicy)

	var ctBuffer *C.uchar
	var ctLen C.size_t
	var res C.int

	if pqcSkBase64 != "" {
		pqcSkBytes, err := base64.StdEncoding.DecodeString(pqcSkBase64)
		if err != nil {
			return logical.ErrorResponse("pqc_private_key must be base64 encoded"), nil
		}
		cPqcSk := (*C.uchar)(C.CBytes(pqcSkBytes))
		defer C.free(unsafe.Pointer(cPqcSk))

		res = C.hybrid_cpabe_encryptBuffer_and_sign_with_scheme(
			cPk, C.size_t(len(pkBytes)),
			cPqcSk, C.size_t(len(pqcSkBytes)),
			cPt, C.size_t(len(ptBytes)),
			cPolicy,
			&ctBuffer, &ctLen,
			cScheme)
	} else {
		res = C.hybrid_cpabe_encryptBuffer_with_scheme(
			cPk, C.size_t(len(pkBytes)),
			cPt, C.size_t(len(ptBytes)),
			cPolicy,
			&ctBuffer, &ctLen,
			cScheme)
	}

	if res != C.HCPABE_SUCCESS {
		return nil, errors.New("encryption failed")
	}

	defer FreeCBytes(ctBuffer)
	ctBytes := C.GoBytes(unsafe.Pointer(ctBuffer), C.int(ctLen))
	ctBase64 := base64.StdEncoding.EncodeToString(ctBytes)

	return &logical.Response{
		Data: map[string]interface{}{
			"ciphertext": ctBase64,
		},
	}, nil
}

func (b *abeBackend) pathDecryptWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	ctBase64 := data.Get("ciphertext").(string)
	skBase64 := data.Get("secret_key").(string)
	pqcPkBase64 := data.Get("pqc_public_key").(string)

	if ctBase64 == "" || skBase64 == "" {
		return logical.ErrorResponse("ciphertext and secret_key are required"), nil
	}

	ctBytes, err := base64.StdEncoding.DecodeString(ctBase64)
	if err != nil {
		return logical.ErrorResponse("ciphertext must be base64 encoded"), nil
	}
	skBytes, err := base64.StdEncoding.DecodeString(skBase64)
	if err != nil {
		return logical.ErrorResponse("secret_key must be base64 encoded"), nil
	}

	cCt := (*C.uchar)(C.CBytes(ctBytes))
	defer C.free(unsafe.Pointer(cCt))

	cSk := (*C.uchar)(C.CBytes(skBytes))
	defer C.free(unsafe.Pointer(cSk))

	var ptBuffer *C.uchar
	var ptLen C.size_t
	var res C.int

	if pqcPkBase64 != "" {
		pqcPkBytes, err := base64.StdEncoding.DecodeString(pqcPkBase64)
		if err != nil {
			return logical.ErrorResponse("pqc_public_key must be base64 encoded"), nil
		}
		cPqcPk := (*C.uchar)(C.CBytes(pqcPkBytes))
		defer C.free(unsafe.Pointer(cPqcPk))

		res = C.hybrid_cpabe_decryptBuffer_and_verify(
			cSk, C.size_t(len(skBytes)),
			cPqcPk, C.size_t(len(pqcPkBytes)),
			cCt, C.size_t(len(ctBytes)),
			&ptBuffer, &ptLen)
	} else {
		res = C.hybrid_cpabe_decryptBuffer(
			cSk, C.size_t(len(skBytes)),
			cCt, C.size_t(len(ctBytes)),
			&ptBuffer, &ptLen)
	}

	if res != C.HCPABE_SUCCESS {
		return nil, errors.New("decryption failed or unauthorized access")
	}

	defer FreeCBytes(ptBuffer)
	ptBytes := C.GoBytes(unsafe.Pointer(ptBuffer), C.int(ptLen))
	ptBase64Output := base64.StdEncoding.EncodeToString(ptBytes)

	return &logical.Response{
		Data: map[string]interface{}{
			"plaintext": ptBase64Output,
		},
	}, nil
}
