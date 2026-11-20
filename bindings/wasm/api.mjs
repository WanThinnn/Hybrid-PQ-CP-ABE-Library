/** High-level API over an initialized Emscripten module (WASM32). */
export const Scheme = Object.freeze({ AC17: 0, TKN20: 1, COVERCRYPT: 2 });

export class AbeError extends Error {
  constructor(code, operation, detail) {
    super(`${operation}: ${detail} (code: ${code})`);
    this.name = new.target.name;
    this.code = code;
    this.operation = operation;
  }
}
export class PolicyMismatchError extends AbeError {}
export class SignatureInvalidError extends AbeError {}

const text = value => {
  if (typeof value !== 'string') throw new TypeError('Expected a string');
  if (value.includes('\0')) throw new TypeError('Embedded NUL is forbidden');
  return value;
};
const schemeValue = value => {
  if (!Object.values(Scheme).includes(value)) throw new RangeError('Unknown ABE scheme');
  return value;
};

/** Owns no keys. Returned byte arrays are copies, independent of the WASM heap. */
export function wrapModule(native) {
  const check = (code, operation) => {
    if (!code) return;
    const ErrorType = code === -3 ? PolicyMismatchError : code === -9 ? SignatureInvalidError : AbeError;
    throw new ErrorType(code, operation, native.ccall('getErrorMessage', 'string', ['number'], [code]));
  };
  const invoke = (name, values, count = 0, scheme) => {
    const inputs = [];
    const outputs = [];
    const args = [];
    const types = [];
    const add = (value, type = 'number') => { args.push(value); types.push(type); };
    const allocate = size => {
      const pointer = native._malloc(size);
      if (!pointer) throw new AbeError(-6, name, 'WASM allocation failed');
      inputs.push(pointer);
      return pointer;
    };
    try {
      for (const value of values) {
        if (value instanceof Uint8Array) {
          const pointer = value.length ? allocate(value.length) : 0;
          if (value.length) native.HEAPU8.set(value, pointer);
          add(pointer);
          add(value.length);
        } else {
          add(text(value), 'string');
        }
      }
      for (let i = 0; i < count; i++) {
        const slot = allocate(8);
        native.HEAPU8.fill(0, slot, slot + 8);
        outputs.push(slot);
        add(slot);
        add(slot + 4);
      }
      if (scheme !== undefined) add(schemeValue(scheme));
      check(native.ccall(name, 'number', types, args), name);
      const view = new DataView(native.HEAPU8.buffer);
      const result = outputs.map(slot => {
        const pointer = view.getUint32(slot, true);
        const length = view.getUint32(slot + 4, true);
        return native.HEAPU8.slice(pointer, pointer + length);
      });
      return count === 1 ? result[0] : count ? result : undefined;
    } finally {
      for (const slot of outputs) {
        const pointer = new DataView(native.HEAPU8.buffer).getUint32(slot, true);
        if (pointer) native._freeBuffer(pointer);
      }
      for (const pointer of inputs) native._free(pointer);
    }
  };
  const bytes = value => {
    if (!(value instanceof Uint8Array)) throw new TypeError('Expected Uint8Array');
    return value;
  };
  return Object.freeze({
    native,
    setup({ scheme = Scheme.COVERCRYPT } = {}) {
      const [publicKey, masterSecretKey] = invoke('hybrid_cpabe_setupBuffer_with_scheme', [], 2, scheme);
      return { publicKey, masterSecretKey };
    },
    setupWithSigning({ scheme = Scheme.COVERCRYPT } = {}) {
      const [publicKey, masterSecretKey, verificationKey, signingKey] =
        invoke('hybrid_cpabe_setupBuffer_with_pqc_scheme', [], 4, scheme);
      return { publicKey, masterSecretKey, verificationKey, signingKey };
    },
    generateSecretKey({ masterSecretKey, attributes, scheme = Scheme.COVERCRYPT }) {
      return invoke('hybrid_cpabe_genkeyBuffer_with_scheme', [bytes(masterSecretKey), text(attributes)], 1, scheme);
    },
    encrypt({ publicKey, plaintext, policy, scheme = Scheme.COVERCRYPT }) {
      return invoke('hybrid_cpabe_encryptBuffer_with_scheme', [bytes(publicKey), bytes(plaintext), text(policy)], 1, scheme);
    },
    decrypt({ secretKey, ciphertext }) {
      return invoke('hybrid_cpabe_decryptBuffer', [bytes(secretKey), bytes(ciphertext)], 1);
    },
    encryptAndSign({ publicKey, signingKey, plaintext, policy, scheme = Scheme.COVERCRYPT }) {
      return invoke('hybrid_cpabe_encryptBuffer_and_sign_with_scheme',
        [bytes(publicKey), bytes(signingKey), bytes(plaintext), text(policy)], 1, scheme);
    },
    decryptAndVerify({ secretKey, verificationKey, ciphertext }) {
      return invoke('hybrid_cpabe_decryptBuffer_and_verify',
        [bytes(secretKey), bytes(verificationKey), bytes(ciphertext)], 1);
    },
    setupFiles({ outputPath, scheme = Scheme.COVERCRYPT }) {
      return invoke('setup_with_scheme', [text(outputPath)], 0, scheme);
    },
    setupFilesWithSigning({ outputPath, scheme = Scheme.COVERCRYPT }) {
      return invoke('hybrid_cpabe_setup_with_pqc_scheme', [text(outputPath)], 0, scheme);
    },
    generateSecretKeyFile({ masterSecretKeyPath, attributes, outputPath, scheme = Scheme.COVERCRYPT }) {
      return invoke('generateSecretKey_with_scheme', [text(masterSecretKeyPath), text(attributes), text(outputPath)], 0, scheme);
    },
    encryptFile({ publicKeyPath, plaintextPath, policy, outputPath, scheme = Scheme.COVERCRYPT }) {
      return invoke('hybrid_cpabe_encrypt_with_scheme',
        [text(publicKeyPath), text(plaintextPath), text(policy), text(outputPath)], 0, scheme);
    },
    decryptFile({ secretKeyPath, ciphertextPath, outputPath }) {
      return invoke('hybrid_cpabe_decrypt', [text(secretKeyPath), text(ciphertextPath), text(outputPath)]);
    },
    encryptAndSignFile({ publicKeyPath, signingKeyPath, plaintextPath, policy, outputPath, scheme = Scheme.COVERCRYPT }) {
      return invoke('hybrid_cpabe_encrypt_and_sign_with_scheme',
        [text(publicKeyPath), text(signingKeyPath), text(plaintextPath), text(policy), text(outputPath)], 0, scheme);
    },
    decryptAndVerifyFile({ secretKeyPath, verificationKeyPath, ciphertextPath, outputPath }) {
      return invoke('hybrid_cpabe_decrypt_and_verify',
        [text(secretKeyPath), text(verificationKeyPath), text(ciphertextPath), text(outputPath)]);
    },
    getVersion() { return native.ccall('getVersion', 'string', [], []); },
  });
}
