export const Scheme: Readonly<{ AC17: 0; TKN20: 1; COVERCRYPT: 2 }>;
export type SchemeValue = typeof Scheme[keyof typeof Scheme];
export const KemMode: Readonly<{ CLASSIC: 0; POST_QUANTUM: 1; HYBRIDIZED: 2 }>;
export type KemModeValue = typeof KemMode[keyof typeof KemMode];
export const MlDsaParameterSet: Readonly<{ ML_DSA_44: 44; ML_DSA_65: 65; ML_DSA_87: 87 }>;
export type MlDsaParameterValue = typeof MlDsaParameterSet[keyof typeof MlDsaParameterSet];
export const MlKemParameterSet: Readonly<{ ML_KEM_512: 512; ML_KEM_768: 768; ML_KEM_1024: 1024 }>;
export type MlKemParameterValue = typeof MlKemParameterSet[keyof typeof MlKemParameterSet];
export interface KeyPair { publicKey: Uint8Array; secretKey: Uint8Array }
export interface KemEncapsulation { ciphertext: Uint8Array; sharedSecret: Uint8Array }
export class AbeError extends Error {
  constructor(code: number, operation: string, detail: string);
  code: number;
  operation: string;
}
export class PolicyMismatchError extends AbeError {}
export class SignatureInvalidError extends AbeError {}
export interface AuthorityKeys {
  publicKey: Uint8Array;
  masterSecretKey: Uint8Array;
}
export interface AuthoritySigningKeys extends AuthorityKeys {
  /** Native setup format: Base64-encoded bytes. */
  verificationKey: Uint8Array;
  signingKey: Uint8Array;
}
export interface SchemeOptions { scheme?: SchemeValue }
export interface NativeModule {
  ccall(name: string, returnType: string | null, argumentTypes: string[], arguments_: unknown[]): any;
  HEAPU8: Uint8Array;
  _malloc(size: number): number;
  _free(pointer: number): void;
  _freeBuffer(pointer: number): void;
  FS: {
    writeFile(path: string, data: string | Uint8Array): void;
    readFile(path: string): Uint8Array;
    mkdir(path: string): void;
    unlink(path: string): void;
  };
  ENV: Record<string, string>;
  [name: string]: any;
}
export interface ModuleOptions {
  preRun?: Array<(module: NativeModule) => void>;
  [name: string]: unknown;
}
/** File paths refer to Emscripten's virtual filesystem, not the host filesystem. */
export interface HybridCpAbe {
  readonly native: NativeModule;
  covercryptSetup(options: { configJson: string; mode?: KemModeValue }): AuthorityKeys;
  aesGcmGenerateKey(options?: { keySizeBits?: 128 | 192 | 256 }): Uint8Array;
  aesGcmEncrypt(options: { key: Uint8Array; iv: Uint8Array; plaintext: Uint8Array; aad?: Uint8Array }): Uint8Array;
  aesGcmDecrypt(options: { key: Uint8Array; iv: Uint8Array; ciphertext: Uint8Array; aad?: Uint8Array }): Uint8Array;
  mlDsaGenerateKeypair(options?: { parameterSet?: MlDsaParameterValue }): KeyPair;
  mlDsaSign(options: { message: Uint8Array; secretKey: Uint8Array; parameterSet?: MlDsaParameterValue }): Uint8Array;
  mlDsaVerify(options: { message: Uint8Array; signature: Uint8Array; publicKey: Uint8Array; parameterSet?: MlDsaParameterValue }): boolean;
  mlKemGenerateKeypair(options?: { parameterSet?: MlKemParameterValue }): KeyPair;
  mlKemEncapsulate(options: { publicKey: Uint8Array; parameterSet?: MlKemParameterValue }): KemEncapsulation;
  mlKemDecapsulate(options: { secretKey: Uint8Array; ciphertext: Uint8Array; parameterSet?: MlKemParameterValue }): Uint8Array;
  setup(options?: SchemeOptions): AuthorityKeys;
  setupWithSigning(options?: SchemeOptions): AuthoritySigningKeys;
  generateSecretKey(options: SchemeOptions & { masterSecretKey: Uint8Array; attributes: string }): Uint8Array;
  encrypt(options: SchemeOptions & { publicKey: Uint8Array; plaintext: Uint8Array; policy: string }): Uint8Array;
  decrypt(options: { secretKey: Uint8Array; ciphertext: Uint8Array }): Uint8Array;
  encryptAndSign(options: SchemeOptions & {
    publicKey: Uint8Array; signingKey: Uint8Array; plaintext: Uint8Array; policy: string;
  }): Uint8Array;
  decryptAndVerify(options: {
    secretKey: Uint8Array; verificationKey: Uint8Array; ciphertext: Uint8Array;
  }): Uint8Array;
  setupFiles(options: SchemeOptions & { outputPath: string }): void;
  setupFilesWithSigning(options: SchemeOptions & { outputPath: string }): void;
  generateSecretKeyFile(options: SchemeOptions & {
    masterSecretKeyPath: string; attributes: string; outputPath: string;
  }): void;
  encryptFile(options: SchemeOptions & {
    publicKeyPath: string; plaintextPath: string; policy: string; outputPath: string;
  }): void;
  decryptFile(options: { secretKeyPath: string; ciphertextPath: string; outputPath: string }): void;
  encryptAndSignFile(options: SchemeOptions & {
    publicKeyPath: string; signingKeyPath: string; plaintextPath: string; policy: string; outputPath: string;
  }): void;
  decryptAndVerifyFile(options: {
    secretKeyPath: string; verificationKeyPath: string; ciphertextPath: string; outputPath: string;
  }): void;
  getVersion(): string;
}
/** Existing raw Emscripten factory, preserved for compatibility. */
export default function createHybridCPABE(options?: ModuleOptions): Promise<NativeModule>;
/** Modern facade with camelCase names, copied buffers and typed native errors. */
export function createHybridCpAbe(options?: ModuleOptions): Promise<HybridCpAbe>;

export interface ModuleCreationOptions { moduleOptions?: ModuleOptions }
export interface CoverCryptOptions {
  config?: Record<string, unknown> | string;
  mode?: KemModeValue;
  /** This CoverCrypt build accepts 768. Other sets are rejected. */
  parameterSet?: MlKemParameterValue;
}
export interface PqCpAbeOptions extends CoverCryptOptions { scheme?: SchemeValue }
export type KeygenOptions = { masterSecretKey: Uint8Array; attributes: string };
export type EncryptOptions = { publicKey: Uint8Array; plaintext: Uint8Array; policy: string };
export type DecryptOptions = { secretKey: Uint8Array; ciphertext: Uint8Array };
export abstract class BaseCPABE {
  constructor(native: NativeModule);
  readonly native: NativeModule;
  readonly api: HybridCpAbe;
  abstract readonly scheme: SchemeValue;
  abstract setup(): AuthorityKeys;
  abstract keygen(options: KeygenOptions): Uint8Array;
  abstract encrypt(options: EncryptOptions): Uint8Array;
  abstract decrypt(options: DecryptOptions): Uint8Array;
  generateSecretKey(options: KeygenOptions): Uint8Array;
  setupWithSigning(): AuthoritySigningKeys;
  encryptAndSign(options: EncryptOptions & { signingKey: Uint8Array }): Uint8Array;
  decryptAndVerify(options: DecryptOptions & { verificationKey: Uint8Array }): Uint8Array;
}
declare class ConcreteCPABE extends BaseCPABE {
  readonly scheme: SchemeValue;
  setup(): AuthorityKeys;
  keygen(options: KeygenOptions): Uint8Array;
  encrypt(options: EncryptOptions): Uint8Array;
  decrypt(options: DecryptOptions): Uint8Array;
}
export class AC17CPABE extends ConcreteCPABE {
  constructor(native: NativeModule);
  static create(options?: ModuleCreationOptions): Promise<AC17CPABE>;
}
export class TKN20CPABE extends ConcreteCPABE {
  constructor(native: NativeModule);
  static create(options?: ModuleCreationOptions): Promise<TKN20CPABE>;
}
export class CoverCryptABE extends ConcreteCPABE {
  constructor(native: NativeModule, options?: CoverCryptOptions);
  static create(options?: CoverCryptOptions & ModuleCreationOptions): Promise<CoverCryptABE>;
  readonly mode: KemModeValue;
  readonly parameterSet: 768;
}
export class PqCpAbe extends ConcreteCPABE {
  constructor(native: NativeModule, options?: PqCpAbeOptions);
  static create(options?: PqCpAbeOptions & ModuleCreationOptions): Promise<PqCpAbe>;
  readonly backend: BaseCPABE;
}
export class AesGcm {
  constructor(native: NativeModule, options?: { keySizeBits?: 128 | 192 | 256 });
  static create(options?: { keySizeBits?: 128 | 192 | 256 } & ModuleCreationOptions): Promise<AesGcm>;
  readonly keySizeBits: 128 | 192 | 256;
  generateKey(): Uint8Array;
  generateNonce(): Uint8Array;
  encrypt(options: { key: Uint8Array; nonce: Uint8Array; plaintext: Uint8Array; aad?: Uint8Array }): Uint8Array;
  decrypt(options: { key: Uint8Array; nonce: Uint8Array; ciphertext: Uint8Array; aad?: Uint8Array }): Uint8Array;
}
export class MlDsa {
  constructor(native: NativeModule, options?: { parameterSet?: MlDsaParameterValue });
  static create(options?: { parameterSet?: MlDsaParameterValue } & ModuleCreationOptions): Promise<MlDsa>;
  readonly parameterSet: MlDsaParameterValue;
  generateKeypair(): KeyPair;
  sign(options: { message: Uint8Array; secretKey: Uint8Array }): Uint8Array;
  verify(options: { message: Uint8Array; signature: Uint8Array; publicKey: Uint8Array }): boolean;
}
export class MlKem {
  constructor(native: NativeModule, options?: { parameterSet?: MlKemParameterValue });
  static create(options?: { parameterSet?: MlKemParameterValue } & ModuleCreationOptions): Promise<MlKem>;
  readonly parameterSet: MlKemParameterValue;
  generateKeypair(): KeyPair;
  encapsulate(options: { publicKey: Uint8Array }): KemEncapsulation;
  decapsulate(options: { secretKey: Uint8Array; ciphertext: Uint8Array }): Uint8Array;
}
