import { pathToFileURL } from 'node:url';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { runSelfTest } from '../../bindings/wasm/selftest.mjs';

const [loader, expectedVersion] = process.argv.slice(2);
const { default: createHybridCPABE } = await import(
  loader ? pathToFileURL(loader).href : '../../lib/wasm/loader.mjs');

await runSelfTest(createHybridCPABE, expectedVersion);
const header = readFileSync(new URL('../../include/hybrid_pq_cp_abe/hybrid-pq-cp-abe.h', import.meta.url), 'utf8');
const symbols = [...header.matchAll(/^\s*LIB_API\s+[^\n(]*?\b(\w+)\s*\(/gm)].map(match => match[1]);
const native = await createHybridCPABE();
assert.ok(symbols.length > 33);
for (const symbol of symbols) assert.equal(typeof native[`_${symbol}`], 'function', symbol);
console.log(`PASS WASM exports: ${symbols.length}/${symbols.length} public C functions available`);
