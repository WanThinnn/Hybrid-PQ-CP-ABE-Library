package abe

/*
#cgo CFLAGS: -I../../../../include
#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
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
				Description: "Base64 ABE public key or exact vault-authority-sha256 reference returned by this mount",
				Required:    true,
			},
			"scheme": {
				Type:        framework.TypeString,
				Description: "ABE Scheme (ac17, tkn20 or covercrypt)",
				Default:     "ac17",
			},
			"pqc_private_key": {
				Type:        framework.TypeString,
				Description: "Base64 encoded PQC ML-DSA Secret Key for signing (optional)",
			},
			"sign": {
				Type:        framework.TypeBool,
				Description: "Optional signature selection. Omit for authority default; true requires a signing key; false disables signing",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathEncryptWrite,
			},
		},
		HelpSynopsis:    "Encrypts data using an ABE policy.",
		HelpDescription: "Uses the stored signing key or an explicit key by default. The optional sign field selects signed/unsigned output explicitly. Returns ciphertext and metadata from this encryption operation.",
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
	b.authorityMu.RLock()
	defer b.authorityMu.RUnlock()
	ptBase64 := data.Get("plaintext").(string)
	policy := data.Get("policy").(string)
	pkBase64 := data.Get("public_key").(string)
	schemeStr := data.Get("scheme").(string)
	pqcSkBase64 := data.Get("pqc_private_key").(string)

	if ptBase64 == "" || policy == "" || pkBase64 == "" {
		return logical.ErrorResponse("plaintext, policy, and public_key are required"), nil
	}

	cScheme, err := nativeScheme(schemeStr)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	ptBytes, err := base64.StdEncoding.DecodeString(ptBase64)
	if err != nil {
		return logical.ErrorResponse("plaintext must be base64 encoded"), nil
	}
	state, err := loadAuthority(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	var pkBytes []byte
	if strings.HasPrefix(pkBase64, publicKeyReferencePrefix) {
		if state == nil || len(state.PK) == 0 || state.Scheme != schemeStr || pkBase64 != state.publicKeyReference() {
			return logical.ErrorResponse("public_key reference differs from the stored authority"), nil
		}
		pkBytes = state.PK
	} else {
		pkBytes, err = base64.StdEncoding.DecodeString(pkBase64)
		if err != nil || len(pkBytes) == 0 {
			return logical.ErrorResponse("public_key must be non-empty base64 or a matching authority reference"), nil
		}
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

	var pqcSkBytes []byte
	if pqcSkBase64 == "" {
		if state != nil {
			pqcSkBytes = state.PQCSecret
		}
	} else {
		var err error
		pqcSkBytes, err = base64.StdEncoding.DecodeString(pqcSkBase64)
		if err != nil {
			return logical.ErrorResponse("pqc_private_key must be base64 encoded"), nil
		}
	}
	if value, present := data.GetOk("sign"); present {
		if value.(bool) && len(pqcSkBytes) == 0 {
			return logical.ErrorResponse("sign=true requires an authority or explicit signing key"), nil
		}
		if !value.(bool) {
			if pqcSkBase64 != "" {
				return logical.ErrorResponse("sign=false conflicts with pqc_private_key"), nil
			}
			pqcSkBytes = nil
		}
	}

	if len(pqcSkBytes) > 0 {
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
		return logical.ErrorResponse(nativeError("encrypt", res).Error()), nil
	}

	defer FreeCBytes(ctBuffer)
	ctBytes := C.GoBytes(unsafe.Pointer(ctBuffer), C.int(ctLen))
	ctBase64 := base64.StdEncoding.EncodeToString(ctBytes)
	// New native encryption always emits the existing v2 envelope. Do not
	// infer historical signature state from an opaque ciphertext header.
	tag := map[string]byte{"ac17": 0, "tkn20": 1, "covercrypt": 2}[schemeStr]
	if len(ctBytes) < 2 || ctBytes[0] != 2 || ctBytes[1] != tag {
		return logical.ErrorResponse("native encryption returned an unsupported ciphertext format"), nil
	}
	fingerprint := sha256.Sum256(pkBytes)
	metadata := map[string]interface{}{
		"schema": 1, "scheme": schemeStr, "backend": "vault", "format": "hybrid-v2",
		"pqc_signed": len(pqcSkBytes) != 0, "keyset_id": hex.EncodeToString(fingerprint[:]),
	}
	if state != nil && state.Scheme == schemeStr && bytes.Equal(state.PK, pkBytes) {
		metadata["authority_revision"] = state.Revision
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"ciphertext":      ctBase64,
			"crypto_metadata": metadata,
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
		return logical.ErrorResponse(nativeError("decrypt", res).Error()), nil
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
