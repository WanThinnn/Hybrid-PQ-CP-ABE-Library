package abe

/*
#cgo CFLAGS: -I../../../cpp/include
#cgo CXXFLAGS: -I../../../cpp/include -O2 -std=c++17
#cgo LDFLAGS: -L../lib -lcryptopp -lrabe_ffi -loqs -lstdc++ -lm -ldl -lpthread
#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
#include <stdlib.h>
*/
import "C"
import (
	"unsafe"
)

// FreeCString frees C strings.
func FreeCString(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

// FreeCBytes frees C bytes.
func FreeCBytes(ptr *C.uchar) {
	C.free(unsafe.Pointer(ptr))
}
