import createNative from './native.mjs';
import { wrapModule } from '../api/functional.mjs';

export class NativePrimitive {
  #api;
  constructor(native) { this.#api = wrapModule(native); }
  get api() { return this.#api; }
  static async create({ moduleOptions = {}, ...options } = {}) {
    return new this(await createNative(moduleOptions), options);
  }
}
