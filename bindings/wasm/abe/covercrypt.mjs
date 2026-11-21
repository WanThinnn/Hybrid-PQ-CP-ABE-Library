import { FunctionalCPABE } from './base.mjs';
import { Scheme, KemMode, MlKemParameterSet } from '../models/enums.mjs';
import { parameterValue } from '../utils/validation.mjs';
import { base64Bytes } from '../utils/encoding.mjs';

export class CoverCryptABE extends FunctionalCPABE {
  #configJson;
  #mode;
  constructor(native, { config, mode = KemMode.HYBRIDIZED, parameterSet = MlKemParameterSet.ML_KEM_768 } = {}) {
    super(native, Scheme.COVERCRYPT);
    parameterValue(parameterSet, MlKemParameterSet);
    if (parameterSet !== 768) throw new RangeError('This CoverCrypt build supports ML-KEM-768; standalone MlKem is independent');
    this.#mode = parameterValue(mode, KemMode);
    if (config === undefined && native.ENV?.HCPABE_COVERCRYPT_CONFIG) {
      config = new TextDecoder().decode(native.FS.readFile(native.ENV.HCPABE_COVERCRYPT_CONFIG));
    }
    if (typeof config === 'string') config = JSON.parse(config);
    if (config !== undefined && (!config || typeof config !== 'object' || Array.isArray(config))) {
      throw new TypeError('config must be a JSON object or JSON text');
    }
    this.#configJson = config === undefined ? undefined : JSON.stringify(config);
  }
  get mode() { return this.#mode; }
  get parameterSet() { return MlKemParameterSet.ML_KEM_768; }
  setup() {
    if (this.#configJson === undefined) throw new TypeError('Provide CoverCrypt config before setup');
    return this.api.covercryptSetup({ configJson: this.#configJson, mode: this.mode });
  }
  setupWithSigning({ mlDsaParameterSet } = {}) {
    const keys = this.setup();
    const { publicKey, secretKey } = this.api.mlDsaGenerateKeypair({ parameterSet: mlDsaParameterSet });
    return { ...keys, verificationKey: base64Bytes(publicKey), signingKey: base64Bytes(secretKey) };
  }
  addDimension(options) { return this.api.covercryptAddDimension({ ...options, mode: this.mode }); }
  addAttribute(options) { return this.api.covercryptAddAttribute(options); }
}
