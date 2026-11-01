package abe

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../include
#cgo linux LDFLAGS: -L${SRCDIR}/../../../../lib -l:libhybrid-pq-cp-abe.so -Wl,-rpath,${SRCDIR}/../../../../lib -Wl,-rpath,$ORIGIN
#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// FreeCString frees C strings.
func FreeCString(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

// FreeCBytes frees C bytes.
func FreeCBytes(ptr *C.uchar) {
	C.freeBuffer(ptr)
}

// All schemes are implemented by the shared native library, never by this plugin.
func nativeScheme(name string) (C.CPABEScheme, error) {
	switch name {
	case "ac17":
		return C.CPABE_SCHEME_AC17, nil
	case "tkn20":
		return C.CPABE_SCHEME_TKN20, nil
	case "covercrypt":
		return C.CPABE_SCHEME_COVERCRYPT, nil
	default:
		return 0, fmt.Errorf("unsupported scheme %q: use ac17, tkn20 or covercrypt", name)
	}
}

func nativeVersion() string { return C.GoString(C.getVersion()) }

func covercryptMode(mode string) (C.int, error) {
	switch mode {
	case "classic":
		return 0, nil
	case "post_quantum":
		return 1, nil
	case "hybridized":
		return 2, nil
	default:
		return 0, fmt.Errorf("invalid Covercrypt mode: use classic, post_quantum or hybridized")
	}
}

func nativeError(operation string, code C.int) error {
	return fmt.Errorf("%s: %s (code: %d)", operation, C.GoString(C.getErrorMessage(code)), int(code))
}
