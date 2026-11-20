"""Conversions at the native ABI boundary."""
from ctypes import c_ubyte

def data(value):
    if not isinstance(value, bytes):
        raise TypeError("Expected bytes for native input")
    # Preserve NULL for zero-size inputs where the C ABI accepts it.
    return (c_ubyte * len(value)).from_buffer_copy(value) if value else None


def text(value):
    if not isinstance(value, str):
        raise TypeError("Expected str")
    if "\x00" in value:
        raise ValueError("Embedded NUL is forbidden")
    return value.encode("utf-8")

