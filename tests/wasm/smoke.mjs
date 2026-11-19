import { pathToFileURL } from 'node:url';
import { runSelfTest } from '../../bindings/wasm/selftest.mjs';

const [loader, expectedVersion] = process.argv.slice(2);
const { default: createHybridCPABE } = await import(
  loader ? pathToFileURL(loader).href : '../../lib/wasm/loader.mjs');

await runSelfTest(createHybridCPABE, expectedVersion);
