import createHybridCPABE from './api/legacy.mjs';
import { wrapModule } from './api/functional.mjs';
export * from './models/enums.mjs';
export * from './utils/errors.mjs';
export { PqCpAbe } from './pq_cp_abe.mjs';
export * from './abe/index.mjs';
export * from './primitives/index.mjs';
export default createHybridCPABE;

/** Modern factory; default export retains the raw-module contract. */
export async function createPqCpAbe(options = {}) {
  return wrapModule(await createHybridCPABE(options));
}
export const createHybridCpAbe = createPqCpAbe;
