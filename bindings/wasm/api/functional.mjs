import { Scheme, KemMode, MlDsaParameterSet, MlKemParameterSet } from '../models/enums.mjs';
import { text, parameterValue } from '../utils/validation.mjs';
import { SignatureInvalidError } from '../utils/errors.mjs';
import { createInvoker } from '../runtime/buffers.mjs';

/** Modern functions bound to a runtime, without storing keys. */
export function wrapModule(native) {
  const invoke = createInvoker(native);
  const bytes = value => {
    if (!(value instanceof Uint8Array)) throw new TypeError('Expected Uint8Array');
    return value;
  };
  const aesInputs = (key, iv) => {
    bytes(key); bytes(iv);
    if (![16, 24, 32].includes(key.length) || iv.length < 12) {
      throw new RangeError('Use a 16/24/32-byte AES key and a nonce of at least 12 bytes');
    }
    return [key, iv];
  };
  return Object.freeze({
    native,
    aesGcmGenerateKey({ keySizeBits = 256 } = {}) {
      if (![128, 192, 256].includes(keySizeBits)) throw new RangeError('Invalid AES key size');
      if (typeof native._aes_gcm_generate_key !== 'function') {
        return globalThis.crypto.getRandomValues(new Uint8Array(keySizeBits / 8));
      }
      return invoke('aes_gcm_generate_key', [keySizeBits], 1);
    },
    aesGcmEncrypt({ key, iv, plaintext, aad = new Uint8Array() }) {
      return invoke('aes_gcm_encrypt', [...aesInputs(key, iv), bytes(plaintext), bytes(aad)], 1);
    },
    aesGcmDecrypt({ key, iv, ciphertext, aad = new Uint8Array() }) {
      return invoke('aes_gcm_decrypt', [...aesInputs(key, iv), bytes(ciphertext), bytes(aad)], 1);
    },
    mlDsaGenerateKeypair({ parameterSet = MlDsaParameterSet.ML_DSA_87 } = {}) {
      parameterValue(parameterSet, MlDsaParameterSet);
      const legacy = parameterSet === 87 && typeof native._ml_dsa_generate_keypair !== 'function';
      const [publicKey, secretKey] = legacy ? invoke('ml_dsa_87_generate_keypair', [], 2)
        : invoke('ml_dsa_generate_keypair', [parameterSet], 2);
      return { publicKey, secretKey };
    },
    mlDsaSign({ message, secretKey, parameterSet = MlDsaParameterSet.ML_DSA_87 }) {
      parameterValue(parameterSet, MlDsaParameterSet);
      if (parameterSet === 87 && typeof native._ml_dsa_sign !== 'function') {
        bytes(secretKey);
        if (secretKey.length !== 4896) throw new RangeError('ML-DSA-87 secret key must be 4896 bytes');
        // The old ABI consumes a pointer without a key-length argument.
        return invoke('ml_dsa_87_sign', [bytes(message), { pointerBytes: secretKey }], 1);
      }
      return invoke('ml_dsa_sign', [parameterValue(parameterSet, MlDsaParameterSet), bytes(message), bytes(secretKey)], 1);
    },
    mlDsaVerify({ message, signature, publicKey, parameterSet = MlDsaParameterSet.ML_DSA_87 }) {
      try {
        parameterValue(parameterSet, MlDsaParameterSet);
        if (parameterSet === 87 && typeof native._ml_dsa_verify !== 'function') {
          bytes(publicKey);
          if (publicKey.length !== 2592) throw new RangeError('ML-DSA-87 public key must be 2592 bytes');
          invoke('ml_dsa_87_verify', [bytes(message), bytes(signature), { pointerBytes: publicKey }]);
        } else invoke('ml_dsa_verify', [parameterSet, bytes(message), bytes(signature), bytes(publicKey)]);
        return true;
      } catch (error) {
        if (error instanceof SignatureInvalidError) return false;
        throw error;
      }
    },
    mlKemGenerateKeypair({ parameterSet = MlKemParameterSet.ML_KEM_768 } = {}) {
      const [publicKey, secretKey] = invoke('ml_kem_generate_keypair', [parameterValue(parameterSet, MlKemParameterSet)], 2);
      return { publicKey, secretKey };
    },
    mlKemEncapsulate({ publicKey, parameterSet = MlKemParameterSet.ML_KEM_768 }) {
      const [ciphertext, sharedSecret] = invoke('ml_kem_encapsulate', [parameterValue(parameterSet, MlKemParameterSet), bytes(publicKey)], 2);
      return { ciphertext, sharedSecret };
    },
    mlKemDecapsulate({ secretKey, ciphertext, parameterSet = MlKemParameterSet.ML_KEM_768 }) {
      return invoke('ml_kem_decapsulate', [parameterValue(parameterSet, MlKemParameterSet), bytes(secretKey), bytes(ciphertext)], 1);
    },
    setup({ scheme = Scheme.COVERCRYPT } = {}) {
      const [publicKey, masterSecretKey] = invoke('hybrid_cpabe_setupBuffer_with_scheme', [], 2, scheme);
      return { publicKey, masterSecretKey };
    },
    covercryptSetup({ configJson, mode = KemMode.HYBRIDIZED }) {
      const [publicKey, masterSecretKey] = invoke('hybrid_cpabe_covercrypt_setupBuffer_from_json',
        [text(configJson), parameterValue(mode, KemMode)], 2);
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
