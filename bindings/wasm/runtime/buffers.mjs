import { AbeError, PolicyMismatchError, SignatureInvalidError } from '../utils/errors.mjs';
import { text, schemeValue } from '../utils/validation.mjs';

/** Owns temporary heap allocations for one synchronous C ABI call. */
export function createInvoker(native) {
  const check = (code, operation) => {
    if (!code) return;
    const ErrorType = code === -3 ? PolicyMismatchError : code === -9 ? SignatureInvalidError : AbeError;
    throw new ErrorType(code, operation, native.ccall('getErrorMessage', 'string', ['number'], [code]));
  };
  const invoke = (name, values, count = 0, scheme) => {
    if (typeof native._getVersion === 'function' && typeof native[`_${name}`] !== 'function') {
      throw new Error(`Native runtime does not export ${name}; rebuild or install a matching release`);
    }
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
        const buffer = value instanceof Uint8Array ? value : value?.pointerBytes;
        if (buffer instanceof Uint8Array) {
          const pointer = buffer.length ? allocate(buffer.length) : 0;
          if (buffer.length) native.HEAPU8.set(buffer, pointer);
          add(pointer);
          if (value instanceof Uint8Array) add(buffer.length);
        } else if (typeof value === 'number' && Number.isSafeInteger(value)) {
          add(value);
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
  return invoke;
}
