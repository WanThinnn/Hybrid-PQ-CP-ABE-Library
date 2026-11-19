#!/usr/bin/env node

import { open, readFile, realpath, rename, stat, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { runSelfTest } from './selftest.mjs';

const schemes = new Map([['ac17', 0], ['tkn20', 1], ['covercrypt', 2]]);
const modes = ['hybridized', 'post_quantum', 'classic'];
const fileCommands = new Map([
  ['genkey', {
    usage: '<master-key> <attributes> <user-key>', inputs: [0], scheme: true,
    symbol: 'generateSecretKey_with_scheme',
  }],
  ['encrypt', {
    usage: '<public-key> <file> <policy> <output>', inputs: [0, 1], scheme: true,
    symbol: 'hybrid_cpabe_encrypt_with_scheme',
  }],
  ['decrypt', {
    usage: '<user-key> <ciphertext> <output>', inputs: [0, 1],
    symbol: 'hybrid_cpabe_decrypt',
  }],
  ['encrypt-pqc', {
    usage: '<public-key> <signing-key> <file> <policy> <output>', inputs: [0, 1, 2], scheme: true,
    symbol: 'hybrid_cpabe_encrypt_and_sign_with_scheme',
  }],
  ['decrypt-pqc', {
    usage: '<user-key> <verification-key> <ciphertext> <output>', inputs: [0, 1, 2],
    symbol: 'hybrid_cpabe_decrypt_and_verify',
  }],
]);
const usages = new Map([
  ['setup', '<directory-or-prefix>'],
  ['setup-pqc', '<directory-or-prefix>'],
  ['version', ''],
  ...Array.from(fileCommands, ([name, command]) => [name, command.usage]),
]);

function help() {
  console.log('Usage: pq-cp-abe [options] <command> [arguments]');
  for (const [name, usage] of usages) console.log(`  ${name} ${usage}`.trimEnd());
  console.log(
    '  --test                         Run the full WASM self-test\n' +
    '  --scheme <name>                covercrypt (default), ac17, or tkn20\n' +
    '  --config <file>                CoverCrypt attributes and dimensions for setup\n' +
    '  --mode <name>                  hybridized (default), post_quantum, or classic\n' +
    '  --help                         Show command usage',
  );
}

class UsageError extends Error {}

function parseArguments(args) {
  const options = new Map();
  const positional = [];
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--') {
      positional.push(...args.slice(index + 1));
      break;
    }
    if (['--scheme', '--config', '--mode'].includes(arg)) {
      const value = args[++index];
      if (!value || value.startsWith('--')) throw new UsageError(`${arg} requires a value`);
      options.set(arg, value);
    } else if (arg.startsWith('-')) {
      throw new UsageError(`Unknown option: ${arg}`);
    } else {
      positional.push(arg);
    }
  }
  const [command, ...operands] = positional;
  if (!usages.has(command)) throw new UsageError(`Unknown command: ${command ?? '(missing)'}`);
  const usage = usages.get(command);
  if (operands.length !== (usage ? usage.split(' ').length : 0)) {
    throw new UsageError(`Usage: pq-cp-abe ${command} ${usage}`.trimEnd());
  }
  const schemeName = options.get('--scheme') ?? 'covercrypt';
  if (!schemes.has(schemeName)) throw new UsageError(`Unknown scheme: ${schemeName}`);
  return { command, operands, options, scheme: schemes.get(schemeName) };
}

function checked(abe, symbol, args) {
  const types = args.map(arg => typeof arg === 'number' ? 'number' : 'string');
  const code = abe.ccall(symbol, 'number', types, args);
  if (code !== 0) {
    const message = abe.ccall('getErrorMessage', 'string', ['number'], [code]);
    throw new Error(`${message} (${code})`);
  }
}

async function writeOutputs(outputs, commit) {
  const files = [];
  try {
    for (const [path, bytes] of outputs) {
      files.push({ path, bytes, handle: await open(path, 'wx', 0o600) });
    }
    if (commit) await commit();
    for (const { handle, bytes } of files) {
      await handle.writeFile(bytes);
      await handle.close();
    }
  } catch (error) {
    await Promise.allSettled(files.map(async ({ path, handle }) => {
      await handle.close();
      await unlink(path);
    }));
    throw error;
  }
  for (const { path } of files) console.log(`Wrote ${path}`);
}

async function initialize(createHybridCPABE, setup, scheme, options) {
  if (!setup || scheme !== schemes.get('covercrypt')) return createHybridCPABE();
  const config = options.get('--config') ?? process.env.HCPABE_COVERCRYPT_CONFIG;
  if (!config) throw new UsageError('CoverCrypt setup requires --config <file> or HCPABE_COVERCRYPT_CONFIG');
  const mode = options.get('--mode') ?? process.env.HCPABE_COVERCRYPT_MODE ?? 'hybridized';
  if (!modes.includes(mode)) throw new UsageError(`Unknown CoverCrypt mode: ${mode}`);
  const dimensions = await readFile(config);
  return createHybridCPABE({ preRun: [module => {
    const path = '/attributes-dimensions.json';
    module.FS.writeFile(path, dimensions);
    module.ENV.HCPABE_COVERCRYPT_CONFIG = path;
    module.ENV.HCPABE_COVERCRYPT_MODE = mode;
  }] });
}

async function setupKeys(abe, output, scheme, signed) {
  const existing = await stat(output).catch(error => {
    if (error.code !== 'ENOENT') throw error;
    return null;
  });
  if (existing && !existing.isDirectory()) throw new Error(`Setup path is an existing file: ${output}`);
  const names = [['cpabe_pk.key', '_pk.key'], ['cpabe_msk.key', '_msk.key']];
  if (signed) names.push(['pqc_pk.key', '_pqc_pk.key'], ['pqc_sk.key', '_pqc_sk.key']);
  abe.FS.mkdir('/authority');
  checked(abe, signed ? 'hybrid_cpabe_setup_with_pqc_scheme' : 'setup_with_scheme', ['/authority', scheme]);
  await writeOutputs(names.map(([name, suffix]) => [
    existing ? join(output, name) : output + suffix,
    abe.FS.readFile(`/authority/${name}`),
  ]));
}

async function issueCoverCryptKey(abe, [master, attributes, output]) {
  // File-based CoverCrypt keygen updates the authority's tracing records.
  const path = await realpath(master);
  const temporary = `${path}.pq-cp-abe.tmp`;
  const staged = await open(temporary, 'wx', 0o600);
  let committed = false;
  try {
    abe.FS.writeFile('/master', await readFile(path));
    checked(abe, 'generateSecretKey_with_scheme', ['/master', attributes, '/output', schemes.get('covercrypt')]);
    await staged.writeFile(abe.FS.readFile('/master'));
    await staged.close();
    await writeOutputs([[output, abe.FS.readFile('/output')]], async () => {
      await rename(temporary, path);
      committed = true;
    });
  } finally {
    await staged.close();
    if (!committed) await unlink(temporary);
  }
}

async function operateOnFiles(abe, command, operands, scheme) {
  const parameters = operands.slice(0, -1);
  for (const index of command.inputs) {
    const path = `/input-${index}`;
    abe.FS.writeFile(path, await readFile(operands[index]));
    parameters[index] = path;
  }
  parameters.push('/output');
  if (command.scheme) parameters.push(scheme);
  checked(abe, command.symbol, parameters);
  await writeOutputs([[operands.at(-1), abe.FS.readFile('/output')]]);
}

async function main(args) {
  if (args.length === 0 || (args.length === 1 && ['-h', '--help'].includes(args[0]))) {
    help();
    return;
  }
  const selfTest = args.length === 1 && args[0] === '--test';
  const parsed = selfTest ? null : parseArguments(args[0] === '--version' ? ['version', ...args.slice(1)] : args);
  const { default: createHybridCPABE } = await import('../../lib/wasm/loader.mjs');
  if (selfTest) {
    await runSelfTest(createHybridCPABE);
    return;
  }
  const { command, operands, options, scheme } = parsed;
  const setup = command === 'setup' || command === 'setup-pqc';
  const abe = await initialize(createHybridCPABE, setup, scheme, options);
  if (command === 'version') {
    console.log(abe.ccall('getVersion', 'string', [], []));
  } else if (setup) {
    await setupKeys(abe, operands[0], scheme, command === 'setup-pqc');
  } else if (command === 'genkey' && scheme === schemes.get('covercrypt')) {
    await issueCoverCryptKey(abe, operands);
  } else {
    await operateOnFiles(abe, fileCommands.get(command), operands, scheme);
  }
}

try {
  await main(process.argv.slice(2));
} catch (error) {
  console.error(`pq-cp-abe: ${error.message}`);
  process.exitCode = error instanceof UsageError ? 2 : 1;
}
