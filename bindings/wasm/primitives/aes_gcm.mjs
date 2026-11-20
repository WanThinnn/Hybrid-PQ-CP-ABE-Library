import { NativePrimitive } from '../runtime/primitive.mjs';

export class AesGcm extends NativePrimitive {
  #bits;
  constructor(native, { keySizeBits = 256 } = {}) {
    super(native);
    if (![128, 192, 256].includes(keySizeBits)) throw new RangeError('AES key size must be 128, 192 or 256 bits');
    this.#bits = keySizeBits;
  }
  get keySizeBits() { return this.#bits; }
  generateKey() { return this.api.aesGcmGenerateKey({ keySizeBits: this.keySizeBits }); }
  generateNonce() { return globalThis.crypto.getRandomValues(new Uint8Array(12)); }
  #checkKey(key) {
    if (!(key instanceof Uint8Array)) throw new TypeError('Expected Uint8Array');
    if (key.length * 8 !== this.keySizeBits) throw new RangeError(`This object requires a ${this.keySizeBits}-bit key`);
  }
  encrypt({ key, nonce, plaintext, aad }) {
    this.#checkKey(key);
    return this.api.aesGcmEncrypt({ key, iv: nonce, plaintext, aad });
  }
  decrypt({ key, nonce, ciphertext, aad }) {
    this.#checkKey(key);
    return this.api.aesGcmDecrypt({ key, iv: nonce, ciphertext, aad });
  }
}
