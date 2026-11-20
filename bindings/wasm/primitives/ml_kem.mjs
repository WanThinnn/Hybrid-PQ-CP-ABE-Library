import { NativePrimitive } from '../runtime/primitive.mjs';
import { MlKemParameterSet } from '../models/enums.mjs';
import { parameterValue } from '../utils/validation.mjs';

export class MlKem extends NativePrimitive {
  #parameter;
  constructor(native, { parameterSet = MlKemParameterSet.ML_KEM_768 } = {}) {
    super(native); this.#parameter = parameterValue(parameterSet, MlKemParameterSet);
  }
  get parameterSet() { return this.#parameter; }
  generateKeypair() { return this.api.mlKemGenerateKeypair({ parameterSet: this.parameterSet }); }
  encapsulate(options) { return this.api.mlKemEncapsulate({ ...options, parameterSet: this.parameterSet }); }
  decapsulate(options) { return this.api.mlKemDecapsulate({ ...options, parameterSet: this.parameterSet }); }
}
