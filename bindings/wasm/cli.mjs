#!/usr/bin/env node

import { open, readFile, realpath, rename, stat, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { runSelfTest } from './selftest.mjs';

const schemes = new Map([['ac17', 0], ['tkn20', 1], ['covercrypt', 2]]);
const modes = ['hybridized', 'post_quantum', 'classic'];
const aliases = new Map([['setup-pqc', 'setup'], ['encrypt-pqc', 'encrypt'], ['decrypt-pqc', 'decrypt']]);
const actions = new Map([['setup', '--with-signing-keys'], ['encrypt', '--sign'], ['decrypt', '--verify']]);
const fieldsByCommand = new Map([
  ['setup', ['--file']],
  ['genkey', ['--master-key', '--attributes', '--user-key']],
  ['encrypt', ['--public-key', '--signing-key', '--file', '--policy', '--ciphertext']],
  ['decrypt', ['--user-key', '--verification-key', '--ciphertext', '--output']],
]);
const fields = new Set([...fieldsByCommand.values()].flat());
const signatureFields = ['--signing-key', '--verification-key'];
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
  ['setup_buffer', ''],
  ['genkey_buffer', '<master-key> <attributes>'],
  ['encrypt_buffer', '<public-key> [signing-key] <text> <policy> <ciphertext>'],
  ['decrypt_buffer', '<user-key> [verification-key] <ciphertext>'],
  ['add_dimension', '<master-key> <dimension-json> <new-prefix>'],
  ['add_attribute', '<master-key> <dimension> <attribute> <new-prefix> [after]'],
  ['version', ''],
  ['genkey', fileCommands.get('genkey').usage],
  ['encrypt', '<public-key> [signing-key] <file> <policy> <ciphertext>'],
  ['decrypt', '<user-key> [verification-key] <ciphertext> <output>'],
]);

function usage(command) {
  const options = fieldsByCommand.get(command);
  const positional = `pq-cp-abe ${command} ${usages.get(command)}`.trimEnd();
  const action = actions.get(command.replace(/_buffer$/, ''));
  if (!options) return `Usage: ${positional}${action ? ` [${action}]` : ''}`;
  const required = options.filter(field => !signatureFields.includes(field));
  const signature = options.find(field => signatureFields.includes(field));
  const signing = action ? ` [${action}${signature ? ` ${signature} FILE` : ''}` +
    `${command === 'decrypt' ? '' : ' [--ml-dsa SET]'}]` : '';
  const aes = command === 'encrypt' ? ' [--aes-bits BITS]' : '';
  return `Usage: pq-cp-abe --${command} ${required.map(field => `${field} VALUE`).join(' ')}${signing}${aes}\n` +
    `   or: ${positional}`;
}

function help(command) {
  if (command) {
    if (!usages.has(command)) throw new UsageError(`Unknown command: ${command}`);
    console.log(usage(command));
    return;
  }
  console.log('Usage: pq-cp-abe <command> [options] [arguments]');
  for (const [name, usage] of usages) console.log(`  ${name} ${usage}`.trimEnd());
  console.log(
    '  --test                         Run the full WASM self-test\n' +
    '  --scheme <name>                covercrypt (default), ac17, or tkn20\n' +
    '  --config <file>                CoverCrypt attributes and dimensions for setup\n' +
    '  --mode <name>                  hybridized (default), post_quantum, or classic\n' +
    '  --with-signing-keys            Generate ML-DSA keys during setup\n' +
    '  --sign                        Sign before encryption\n' +
    '  --verify                      Require a valid signature on decryption\n' +
    '  --aes-bits <bits>               128, 192, or 256 (default)\n' +
    '  --ml-dsa <set>                  44, 65, or 87 (default)\n' +
    '  --help                         Use <command> --help for command arguments',
  );
}

class UsageError extends Error {}

function parseArguments(args) {
  const options = new Map();
  const named = new Map();
  const flags = new Set();
  const positional = [];
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--') {
      positional.push(...args.slice(index + 1));
      break;
    }
    if (positional.length === 0 && arg.startsWith('--') && fieldsByCommand.has(arg.slice(2))) {
      positional.push(arg.slice(2));
    } else if (arg === '--pqc' || [...actions.values()].includes(arg)) {
      flags.add(arg);
    } else if (['--scheme', '--config', '--mode', '--aes-bits', '--ml-dsa'].includes(arg) || fields.has(arg)) {
      const value = args[++index];
      const target = fields.has(arg) ? named : options;
      if (value === undefined || value.startsWith('--')) throw new UsageError(`${arg} requires a value`);
      if (target.has(arg)) throw new UsageError(`${arg} was specified more than once`);
      target.set(arg, value);
    } else if (arg.startsWith('-')) {
      throw new UsageError(`Unknown option: ${arg}`);
    } else {
      positional.push(arg);
    }
  }
  const [invoked, ...operands] = positional;
  const command = aliases.get(invoked) ?? invoked;
  if (!usages.has(command)) throw new UsageError(`Unknown command: ${command ?? '(missing)'}`);
  const fail = message => { throw new UsageError(`${message}\n${usage(command)}`); };
  const base = command.replace(/_buffer$/, '');
  const action = actions.get(base);
  for (const flag of flags) {
    if (flag !== '--pqc' && flag !== action) fail(`${flag} is not valid for ${command}`);
  }
  const modernSigning = flags.has(action);
  const signed = aliases.has(invoked) || flags.has('--pqc') || modernSigning;
  if (signed && !action) fail(`Signature options are not valid for ${command}`);
  const aesBits = options.get('--aes-bits');
  const mlDsa = options.get('--ml-dsa');
  if (aesBits !== undefined && (base !== 'encrypt' || !['128', '192', '256'].includes(aesBits))) {
    fail('--aes-bits requires 128, 192 or 256 on encryption');
  }
  if (mlDsa !== undefined && (!signed || !['setup', 'encrypt'].includes(base) || !['44', '65', '87'].includes(mlDsa))) {
    fail('--ml-dsa requires 44, 65 or 87 with --with-signing-keys on setup or --sign on encryption');
  }
  let expected = fieldsByCommand.get(command);
  if (named.size) {
    if (operands.length || !expected) fail('Use named arguments on their own with setup, genkey, encrypt, or decrypt');
    if (command === 'setup' && named.has('--output')) {
      if (named.has('--file')) fail('Specify only one of --file and --output');
      named.set('--file', named.get('--output'));
      named.delete('--output');
    }
    if (!signed) expected = expected.filter(field => !signatureFields.includes(field));
    for (const field of named.keys()) if (!expected.includes(field)) fail(`${field} is not valid for ${command}`);
    for (const field of expected) {
      if (!named.has(field)) fail(`${command} requires ${field}`);
      operands.push(named.get(field));
    }
  } else {
    const positionFields = usages.get(command).split(' ').filter(Boolean);
    const omitted = Number(!signed && positionFields.some(field => /\[(signing|verification)-key\]/.test(field)));
    const count = positionFields.length - omitted;
    if (operands.length !== count && !(command === 'add_attribute' && operands.length === count - 1)) {
      fail(`Incorrect number of arguments for ${command}`);
    }
  }
  const schemeName = options.get('--scheme') ?? 'covercrypt';
  if (!schemes.has(schemeName)) throw new UsageError(`Unknown scheme: ${schemeName}`);
  return { command, operands, options, scheme: schemes.get(schemeName), signed, modernSigning,
    aesBits: aesBits === undefined ? undefined : Number(aesBits), mlDsa: mlDsa === undefined ? undefined : Number(mlDsa) };
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

async function initialize(createHybridCPABE, { command, scheme, options }) {
  const setup = command === 'setup' || command === 'setup_buffer';
  const growth = command === 'add_dimension' || command === 'add_attribute';
  if (scheme !== schemes.get('covercrypt') || !(setup || growth)) return createHybridCPABE();
  const config = options.get('--config') ?? process.env.HCPABE_COVERCRYPT_CONFIG;
  if (setup && !config) throw new UsageError('CoverCrypt setup requires --config <file> or HCPABE_COVERCRYPT_CONFIG');
  const mode = options.get('--mode') ?? process.env.HCPABE_COVERCRYPT_MODE ?? 'hybridized';
  if (!modes.includes(mode)) throw new UsageError(`Unknown CoverCrypt mode: ${mode}`);
  const dimensions = setup ? await readFile(config) : null;
  return createHybridCPABE({ preRun: [module => {
    const path = '/attributes-dimensions.json';
    if (dimensions) {
      module.FS.writeFile(path, dimensions);
      module.ENV.HCPABE_COVERCRYPT_CONFIG = path;
    }
    module.ENV.HCPABE_COVERCRYPT_MODE = mode;
  }] });
}

function keyPaths(output, directory) {
  return [
    [directory ? join(output, 'cpabe_pk.key') : output + '_pk.key', 'cpabe_pk.key'],
    [directory ? join(output, 'cpabe_msk.key') : output + '_msk.key', 'cpabe_msk.key'],
  ];
}

async function setupKeys(abe, output, { scheme, signed, modernSigning, mlDsa }) {
  const existing = await stat(output).catch(error => {
    if (error.code !== 'ENOENT') throw error;
    return null;
  });
  if (existing && !existing.isDirectory()) throw new Error(`Setup path is an existing file: ${output}`);
  const names = keyPaths(output, existing);
  if (signed) {
    const label = modernSigning ? 'ml-dsa' : 'pqc';
    for (const key of ['pk', 'sk']) {
      const name = `${label}_${key}.key`;
      names.push([existing ? join(output, name) : `${output}_${name}`, name]);
    }
  }
  abe.FS.mkdir('/authority');
  const native = ['/authority', scheme];
  if (modernSigning) checked(abe, 'hybrid_cpabe_setup_with_signing_keys', [...native, mlDsa ?? 87]);
  else if (signed && mlDsa !== undefined) checked(abe, 'hybrid_cpabe_setup_with_ml_dsa', [...native, mlDsa]);
  else checked(abe, signed ? 'hybrid_cpabe_setup_with_pqc_scheme' : 'setup_with_scheme', native);
  await writeOutputs(names.map(([path, name]) => [path, abe.FS.readFile(`/authority/${name}`)]));
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

async function operateOnFiles(abe, command, operands, scheme, extraParameters = []) {
  const parameters = operands.slice(0, -1);
  for (const index of command.inputs) {
    const path = `/input-${index}`;
    abe.FS.writeFile(path, await readFile(operands[index]));
    parameters[index] = path;
  }
  parameters.push('/output');
  if (command.scheme) parameters.push(scheme);
  checked(abe, command.symbol, [...parameters, ...extraParameters]);
  await writeOutputs([[operands.at(-1), abe.FS.readFile('/output')]]);
}

async function growAuthority(abe, command, [master, first, second, prefix, after]) {
  abe.FS.writeFile('/master', await readFile(master));
  if (command === 'add_dimension') {
    checked(abe, 'hybrid_cpabe_covercrypt_add_dimension', ['/master', await readFile(first, 'utf8'), '/updated']);
  } else {
    checked(abe, 'hybrid_cpabe_covercrypt_add_attribute', ['/master', first, second, after ?? 0, '/updated']);
  }
  const output = command === 'add_dimension' ? second : prefix;
  const existing = await stat(output).catch(error => {
    if (error.code !== 'ENOENT') throw error;
    return null;
  });
  if (existing && !existing.isDirectory()) throw new Error(`Growth path is an existing file: ${output}`);
  await writeOutputs(keyPaths(output, existing).map(([path, name]) => [
    path, abe.FS.readFile(name === 'cpabe_pk.key' ? '/updated_pk.key' : '/updated_msk.key'),
  ]));
}

async function runBufferCommand(abe, { command, operands, scheme, signed, aesBits, mlDsa }) {
  const args = [...operands];
  const inputCount = { setup_buffer: 0, genkey_buffer: 1, encrypt_buffer: signed ? 2 : 1,
    decrypt_buffer: signed ? 3 : 2 }[command];
  for (let index = 0; index < inputCount; index++) {
    const path = `/input-${index}`;
    abe.FS.writeFile(path, await readFile(args[index]));
    args[index] = path;
  }
  if (command === 'encrypt_buffer') args[args.length - 1] = '/output';
  const schemeName = [...schemes.keys()][scheme];
  const flags = ['--scheme', schemeName];
  if (signed) flags.push('--pqc');
  if (aesBits !== undefined) flags.push('--aes-bits', String(aesBits));
  if (mlDsa !== undefined) flags.push('--ml-dsa', String(mlDsa));
  const status = abe.callMain([command, ...flags, ...args]);
  if (status) throw new Error(`${command} failed with status ${status}`);
  if (command === 'encrypt_buffer') await writeOutputs([[operands.at(-1), abe.FS.readFile('/output')]]);
}

async function main(args) {
  if (!args.length || (args.length === 1 && ['-h', '--help', 'help'].includes(args[0]))) {
    help();
    return;
  }
  if (args.length === 2 && (args[0] === 'help' || ['-h', '--help'].includes(args[1]))) {
    const invoked = (args[0] === 'help' ? args[1] : args[0]).replace(/^--/, '');
    help(aliases.get(invoked) ?? invoked);
    return;
  }
  const selfTest = args.length === 1 && args[0] === '--test';
  const version = args.length === 1 && ['-v', '--version'].includes(args[0]);
  const parsed = selfTest ? null : parseArguments(version ? ['version'] : args);
  const { default: createHybridCPABE } = await import('../../lib/wasm/loader.mjs');
  if (selfTest) {
    await runSelfTest(createHybridCPABE);
    return;
  }
  const { command, operands, scheme, signed, aesBits, mlDsa } = parsed;
  const abe = await initialize(createHybridCPABE, parsed);
  if (command === 'version') {
    console.log(abe.ccall('getVersion', 'string', [], []));
  } else if (command === 'setup') {
    await setupKeys(abe, operands[0], parsed);
  } else if (command === 'genkey' && scheme === schemes.get('covercrypt')) {
    await issueCoverCryptKey(abe, operands);
  } else if (command === 'add_dimension' || command === 'add_attribute') {
    if (scheme !== schemes.get('covercrypt')) throw new UsageError('Authority growth requires --scheme covercrypt');
    await growAuthority(abe, command, operands);
  } else if (command.endsWith('_buffer')) {
    await runBufferCommand(abe, parsed);
  } else {
    const operation = fileCommands.get(signed ? `${command}-pqc` : command);
    const parameters = [];
    if (command === 'encrypt' && (aesBits !== undefined || mlDsa !== undefined)) {
      parameters.push(aesBits ?? 256);
      if (signed) parameters.push(mlDsa ?? 87);
      const symbol = signed ? 'hybrid_cpabe_encrypt_and_sign_with_params' : 'hybrid_cpabe_encrypt_with_params';
      await operateOnFiles(abe, { ...operation, symbol }, operands, scheme, parameters);
    } else {
      await operateOnFiles(abe, operation, operands, scheme);
    }
  }
}

try {
  await main(process.argv.slice(2));
} catch (error) {
  console.error(`pq-cp-abe: ${error.message}`);
  process.exitCode = error instanceof UsageError ? 2 : 1;
}
