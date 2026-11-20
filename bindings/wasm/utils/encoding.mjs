/** Native combined-signing APIs use Base64 ASCII bytes rather than raw keys. */
export function base64Bytes(bytes) {
  return new TextEncoder().encode(btoa(String.fromCharCode(...bytes)));
}
