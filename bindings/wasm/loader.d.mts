export const Scheme: Readonly<{ AC17: 0; TKN20: 1; COVERCRYPT: 2 }>;
export type SchemeValue = typeof Scheme[keyof typeof Scheme];
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
