import { NativePrimitive } from '../runtime/primitive.mjs';
import { MlDsaParameterSet } from '../models/enums.mjs';
import { parameterValue } from '../utils/validation.mjs';

export class MlDsa extends NativePrimitive {
  #parameter;
  constructor(native, { parameterSet = MlDsaParameterSet.ML_DSA_87 } = {}) {
    super(native); this.#parameter = parameterValue(parameterSet, MlDsaParameterSet);
  }
  get parameterSet() { return this.#parameter; }
  generateKeypair() { return this.api.mlDsaGenerateKeypair({ parameterSet: this.parameterSet }); }
  sign(options) { return this.api.mlDsaSign({ ...options, parameterSet: this.parameterSet }); }
  verify(options) { return this.api.mlDsaVerify({ ...options, parameterSet: this.parameterSet }); }
}
