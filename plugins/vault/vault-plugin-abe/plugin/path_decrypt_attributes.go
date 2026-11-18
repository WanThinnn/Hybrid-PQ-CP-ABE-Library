package abe

/*
#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"

static void wipe_buffer(unsigned char *data, size_t len) {
	volatile unsigned char *p = data;
	while (p && len--) *p++ = 0;
}
*/
import "C"

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"unsafe"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathDecryptWithAttributes(b *abeBackend) *framework.Path {
	fields := make(map[string]*framework.FieldSchema)
	for key, description := range map[string]string{
		"ciphertext":         "Base64 encoded CP-ABE ciphertext.",
		"attributes":         "Space-separated attributes for this read.",
		"scheme":             "Expected ABE scheme.",
		"format":             "Expected ciphertext envelope format.",
		"keyset_id":          "Expected public key SHA-256 fingerprint.",
		"authority_revision": "Expected authority revision as a decimal string.",
		"signature_mode":     "Required verification mode: required or unsigned.",
	} {
		fields[key] = &framework.FieldSchema{Type: framework.TypeString, Required: true, Description: description}
	}
	return &framework.Path{
		Pattern: "decrypt_with_attributes",
		Fields:  fields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathDecryptWithAttributesWrite},
		},
		HelpSynopsis: "Decrypts with an ephemeral attribute key that stays inside the plugin.",
	}
}

func (b *abeBackend) pathDecryptWithAttributesWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	scheme := data.Get("scheme").(string)
	cScheme, err := nativeScheme(scheme)
	if err != nil {
		return logical.ErrorResponse("unsupported ABE scheme"), nil
	}
	attrs := data.Get("attributes").(string)
	if strings.TrimSpace(attrs) == "" || strings.ContainsRune(attrs, 0) {
		return logical.ErrorResponse("invalid attributes"), nil
	}
	signatureMode := data.Get("signature_mode").(string)
	if signatureMode != "required" && signatureMode != "unsigned" {
		return logical.ErrorResponse("invalid signature mode"), nil
	}
	rev, err := strconv.ParseUint(data.Get("authority_revision").(string), 10, 64)
	if err != nil || rev == 0 {
		return logical.ErrorResponse("invalid authority revision"), nil
	}
	ct, err := base64.StdEncoding.Strict().DecodeString(data.Get("ciphertext").(string))
	if err != nil || len(ct) < 2 {
		return logical.ErrorResponse("invalid ciphertext"), nil
	}
	format := data.Get("format").(string)
	tag := map[string]byte{"ac17": 0, "tkn20": 1, "covercrypt": 2}[scheme]
	switch {
	case format == "hybrid-v1" && scheme == "ac17" && ct[0] == 1:
	case format == "hybrid-v2" && ct[0] == 2 && ct[1] == tag:
	default:
		return logical.ErrorResponse("ciphertext does not match the expected scheme and format"), nil
	}

	b.authorityMu.RLock()
	defer b.authorityMu.RUnlock()
	state, err := loadAuthority(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return logical.ErrorResponse("authority is unavailable"), nil
	}
	defer clear(state.MSK)
	defer clear(state.PQCSecret)
	if len(state.MSK) == 0 || state.Scheme != scheme || state.Revision != rev ||
		state.publicKeyFingerprint() != data.Get("keyset_id").(string) {
		return logical.ErrorResponse("authority identity differs"), nil
	}
	if signatureMode == "required" && len(state.PQCPublic) == 0 {
		return logical.ErrorResponse("signature verifier is unavailable"), nil
	}

	cAttrs := C.CString(attrs)
	defer FreeCString(cAttrs)
	var sk *C.uchar
	var skLen C.size_t
	res := C.hybrid_cpabe_genkeyBuffer_with_scheme(
		(*C.uchar)(unsafe.Pointer(&state.MSK[0])), C.size_t(len(state.MSK)), cAttrs, &sk, &skLen, cScheme)
	if sk != nil {
		defer FreeCBytes(sk)
		defer C.wipe_buffer(sk, skLen)
	}
	if res != C.HCPABE_SUCCESS || sk == nil || skLen == 0 {
		return logical.ErrorResponse("attribute key generation failed"), nil
	}

	ciphertext := (*C.uchar)(unsafe.Pointer(&ct[0]))
	var pt *C.uchar
	var ptLen C.size_t
	if signatureMode == "required" {
		res = C.hybrid_cpabe_decryptBuffer_and_verify(sk, skLen,
			(*C.uchar)(unsafe.Pointer(&state.PQCPublic[0])), C.size_t(len(state.PQCPublic)),
			ciphertext, C.size_t(len(ct)), &pt, &ptLen)
	} else {
		res = C.hybrid_cpabe_decryptBuffer(sk, skLen, ciphertext, C.size_t(len(ct)), &pt, &ptLen)
	}
	if pt != nil {
		defer FreeCBytes(pt)
		defer C.wipe_buffer(pt, ptLen)
	}
	if res != C.HCPABE_SUCCESS {
		return logical.ErrorResponse("decryption or signature verification failed"), nil
	}
	return &logical.Response{Data: map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(unsafe.Slice((*byte)(unsafe.Pointer(pt)), int(ptLen))),
	}}, nil
}
