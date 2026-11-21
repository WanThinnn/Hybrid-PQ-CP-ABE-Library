import { BaseCPABE } from './abe/base.mjs';
import { AC17CPABE } from './abe/ac17.mjs';
import { TKN20CPABE } from './abe/tkn20.mjs';
import { CoverCryptABE } from './abe/covercrypt.mjs';
import { Scheme, KemMode } from './models/enums.mjs';
import { schemeValue } from './utils/validation.mjs';

export class PqCpAbe extends BaseCPABE {
  #backend;
  constructor(native, { scheme = Scheme.COVERCRYPT, config, mode = KemMode.HYBRIDIZED, parameterSet = 768 } = {}) {
    super(native);
    schemeValue(scheme);
    if (scheme === Scheme.COVERCRYPT) this.#backend = new CoverCryptABE(native, { config, mode, parameterSet });
    else {
      if (config !== undefined || mode !== KemMode.HYBRIDIZED || parameterSet !== 768) {
        throw new TypeError('config, mode and parameterSet apply only to CoverCrypt');
      }
      this.#backend = scheme === Scheme.AC17 ? new AC17CPABE(native) : new TKN20CPABE(native);
    }
  }
  get backend() { return this.#backend; }
  get scheme() { return this.backend.scheme; }
  setup() { return this.backend.setup(); }
  setupWithSigning(options) { return this.backend.setupWithSigning(options); }
  keygen(options) { return this.backend.keygen(options); }
  encrypt(options) { return this.backend.encrypt(options); }
  decrypt(options) { return this.backend.decrypt(options); }
}
