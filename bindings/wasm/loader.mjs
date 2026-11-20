import { wrapModule } from './api.mjs';
export { Scheme, AbeError, PolicyMismatchError, SignatureInvalidError } from './api.mjs';

/** Modern API; the default createHybridCPABE export remains the raw module. */
export async function createHybridCpAbe(options = {}) {
  return wrapModule(await createHybridCPABE(options));
}

// Keep one persistent Go runtime, shared by independent Emscripten instances.
let runtime;
async function readBinary(url) {
  if (url.protocol === 'file:') {
    const { readFile } = await import('node:fs/promises');
    return readFile(url);
  }
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Cannot load ${url}: ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}
async function startTKN20() {
  if (!globalThis.crypto && typeof process !== 'undefined') {
    globalThis.crypto = (await import('node:crypto')).webcrypto;
  }
  await import('./wasm_exec.js');
  const go = new globalThis.Go();
  const { instance } = await WebAssembly.instantiate(
    await readBinary(new URL('./tkn20.wasm', import.meta.url)), go.importObject);
  // run() registers the callback synchronously before Go parks in select{}.
  const running = go.run(instance);
  running.catch(error => console.error('TKN20 runtime terminated:', error));
  if (typeof globalThis.__hybridTKN20 !== 'function') {
    throw new Error('TKN20 runtime did not initialize');
  }
  return globalThis.__hybridTKN20;
}
export default async function createHybridCPABE(options = {}) {
  runtime ??= startTKN20();
  const tkn20 = await runtime;
  const imported = await import('./hybrid-pq-cp-abe.mjs');
  const factory = imported.default ?? globalThis.createHybridCPABE;
  const wasmBinary = await readBinary(new URL('./hybrid-pq-cp-abe.wasm', import.meta.url));
  return factory({ ...options, wasmBinary, tkn20, noInitialRun: true });
}
