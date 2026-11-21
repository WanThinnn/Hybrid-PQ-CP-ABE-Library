import createNative from '../runtime/native.mjs';
import { wrapModule } from '../api/functional.mjs';

/** Scheme objects keep configuration and a runtime reference, never keys. */
export class BaseCPABE {
  #api;
  constructor(native) {
    if (new.target === BaseCPABE) throw new TypeError('BaseCPABE is abstract');
    this.#api = wrapModule(native);
  }
  static async create({ moduleOptions = {}, ...options } = {}) {
    if (this === BaseCPABE) throw new TypeError('BaseCPABE is abstract');
    return new this(await createNative(moduleOptions), options);
  }
  get api() { return this.#api; }
  get native() { return this.api.native; }
  get scheme() { throw new TypeError('Implement scheme'); }
  setup() { throw new TypeError('Implement setup'); }
  keygen() { throw new TypeError('Implement keygen'); }
  encrypt() { throw new TypeError('Implement encrypt'); }
  decrypt() { throw new TypeError('Implement decrypt'); }
  generateSecretKey(options) { return this.keygen(options); }
  setupWithSigning(options) { return this.api.setupWithSigning({ ...options, scheme: this.scheme }); }
  encryptAndSign(options) { return this.api.encryptAndSign({ ...options, scheme: this.scheme }); }
  decryptAndVerify(options) { return this.api.decryptAndVerify(options); }
}

export class FunctionalCPABE extends BaseCPABE {
  #scheme;
  constructor(native, scheme) { super(native); this.#scheme = scheme; }
  get scheme() { return this.#scheme; }
  setup() { return this.api.setup({ scheme: this.scheme }); }
  keygen(options) { return this.api.generateSecretKey({ ...options, scheme: this.scheme }); }
  encrypt(options) { return this.api.encrypt({ ...options, scheme: this.scheme }); }
  decrypt(options) { return this.api.decrypt(options); }
}
