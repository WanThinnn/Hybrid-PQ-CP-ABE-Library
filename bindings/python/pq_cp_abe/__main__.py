"""Command line for the Python 6.1 bindings."""
import argparse
import base64
import os
from pathlib import Path
import sys

from .api import functional as api, legacy
from .models import Scheme
from .utils.errors import check_status

_SCHEMES = {scheme.name.lower(): scheme for scheme in Scheme}
_FILE_FIELDS = {
    "setup": ("file",),
    "genkey": ("master-key", "attributes", "user-key"),
    "encrypt": ("public-key", "signing-key", "file", "policy", "ciphertext"),
    "decrypt": ("user-key", "verification-key", "ciphertext", "output"),
}
_POSITIONS = {
    "setup_buffer": (),
    "genkey_buffer": ("master-key", "attributes"),
    "encrypt_buffer": ("public-key", "signing-key", "text", "policy", "ciphertext"),
    "decrypt_buffer": ("user-key", "verification-key", "ciphertext"),
    "add_dimension": ("master-key", "dimension-json", "new-prefix"),
    "add_attribute": ("master-key", "dimension", "attribute", "new-prefix", "after"),
    "test-buf": ("public-key", "user-key"),
    "version": (),
}
_ALIASES = {"setup-pqc": "setup", "encrypt-pqc": "encrypt", "decrypt-pqc": "decrypt"}
_ACTIONS = {"setup": "with-signing-keys", "encrypt": "sign", "decrypt": "verify"}
_SIGNATURE_FIELDS = {"signing-key", "verification-key"}


class _NamedArgument(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} was specified more than once")
        setattr(namespace, self.dest, values)


def _command_usage(command):
    canonical = _ALIASES.get(command, command)
    if canonical in _FILE_FIELDS:
        fields = _FILE_FIELDS[canonical]
        named = " ".join(f"--{field} <{field}>" for field in fields if field not in _SIGNATURE_FIELDS)
        action = _ACTIONS.get(canonical)
        if action:
            signature = next((field for field in fields if field in _SIGNATURE_FIELDS), None)
            action_options = f"--{action}"
            if signature:
                action_options += f" --{signature} <{signature}>"
            if canonical in ("setup", "encrypt"):
                action_options += " [--ml-dsa {44,65,87}]"
            named += f" [{action_options}]"
        if canonical == "encrypt":
            named += " [--aes-bits {128,192,256}]"
        positional = " ".join(f"[<{field}>]" if field in _SIGNATURE_FIELDS else f"<{field}>" for field in fields)
        return f"Usage: pq-cp-abe --{canonical} {named}\n   or: pq-cp-abe {command} {positional}"
    fields = " ".join(f"<{field}>" for field in _POSITIONS[canonical])
    action = _ACTIONS.get(canonical.removesuffix("_buffer"))
    return f"Usage: pq-cp-abe {canonical} {fields}" + (f" [--{action}]" if action else "")


def _parser():
    parser = argparse.ArgumentParser(
        prog="pq-cp-abe", usage="%(prog)s <command> [options] [arguments]", allow_abbrev=False,
        description="PQ-CP-ABE Python CLI. Use <command> --help for command arguments.",
        epilog="Commands: setup, genkey, encrypt, decrypt, setup_buffer, genkey_buffer, "
               "encrypt_buffer, decrypt_buffer, add_dimension, add_attribute, version, help")
    aliases = parser.add_mutually_exclusive_group()
    for command in _FILE_FIELDS:
        aliases.add_argument(f"--{command}", dest="command", action="store_const", const=command,
                             help=f"Run {command} with named arguments")
    parser.add_argument("operands", nargs="*", metavar="ARG")
    parser.add_argument("--scheme", choices=_SCHEMES, default="covercrypt")
    parser.add_argument("--config", metavar="FILE", help="CoverCrypt JSON dimensions")
    parser.add_argument("--mode", choices=("classic", "post_quantum", "hybridized"), help="CoverCrypt encapsulation mode")
    parser.add_argument("--aes-bits", type=int, choices=(128, 192, 256))
    parser.add_argument("--ml-dsa", type=int, choices=(44, 65, 87))
    parser.add_argument("--version", "-v", action="store_true")
    parser.add_argument("--test", action="store_true", help="Run the native self-test")
    parser.add_argument("--pqc", action="store_true", help=argparse.SUPPRESS)
    for action in _ACTIONS.values():
        parser.add_argument(f"--{action}", action="store_true")
    for field in sorted({field for fields in _FILE_FIELDS.values() for field in fields}):
        parser.add_argument(f"--{field}", metavar="VALUE", action=_NamedArgument)
    return parser


def _resolve(parser, options):
    positional = list(options.operands)
    invoked = options.command or (positional.pop(0) if positional else "")
    command = _ALIASES.get(invoked, invoked)
    if command not in _FILE_FIELDS and command not in _POSITIONS:
        parser.error(f"Unknown command: {invoked or '(missing)'}")

    def fail(message):
        parser.exit(2, f"{parser.prog}: {message}\n{_command_usage(invoked)}\n")

    base = command.removesuffix("_buffer")
    action = _ACTIONS.get(base)
    for flag in _ACTIONS.values():
        if getattr(options, flag.replace("-", "_")) and action != flag:
            fail(f"--{flag} is not valid for {command}")
    modern_signing = action is not None and getattr(options, action.replace("-", "_"))
    signed = invoked in _ALIASES or options.pqc or modern_signing
    if signed and action is None:
        fail(f"Signature options are not valid for {command}")
    if options.aes_bits is not None and base != "encrypt":
        fail("--aes-bits is for encryption")
    if options.ml_dsa is not None and (base not in ("setup", "encrypt") or not signed):
        fail("--ml-dsa requires --with-signing-keys on setup or --sign on encryption")

    named = {field: getattr(options, field.replace("-", "_"))
             for fields in _FILE_FIELDS.values() for field in fields
             if getattr(options, field.replace("-", "_")) is not None}
    if command == "setup" and "output" in named:
        if "file" in named:
            fail("Specify only one of --file and --output")
        named["file"] = named.pop("output")
    fields = _FILE_FIELDS.get(command, _POSITIONS.get(command))
    if not signed:
        fields = tuple(field for field in fields if field not in _SIGNATURE_FIELDS)
    if named:
        if command not in _FILE_FIELDS or positional:
            fail("Use named arguments on their own with setup, genkey, encrypt, or decrypt")
        for field in named:
            if field not in fields:
                fail(f"--{field} is not valid for {command}")
        for field in fields:
            if field not in named:
                fail(f"{command} requires --{field}")
        positional = [named[field] for field in fields]
    if len(positional) != len(fields) and not (command == "add_attribute" and len(positional) == 4):
        fail(f"Incorrect number of arguments for {command}")
    return command, positional, signed, modern_signing


def _buffer_command(command, args, scheme, signed, aes_bits, ml_dsa):
    def key(path):
        return base64.b64decode(Path(path).read_bytes())

    if command == "setup_buffer":
        keys = api.setup_with_signing(scheme=scheme, ml_dsa_parameter_set=ml_dsa) if signed else api.setup(scheme=scheme)
        labels = ("PUBLIC KEY", "MASTER SECRET KEY", "PQC PUBLIC KEY", "PQC SECRET KEY")
        for label, value in zip(labels, keys):
            print(f"--- {label} (Base64) ---\n{base64.b64encode(value).decode('ascii')}")
    elif command == "genkey_buffer":
        result = api.generate_secret_key(key(args[0]), args[1], scheme=scheme)
        print(f"--- SECRET KEY (Base64) ---\n{base64.b64encode(result).decode('ascii')}")
    elif command == "encrypt_buffer":
        data, policy, output = args[-3:]
        if signed:
            result = api.encrypt_and_sign(key(args[0]), key(args[1]), data.encode(), policy,
                                          scheme=scheme, aes_key_bits=aes_bits, ml_dsa_parameter_set=ml_dsa)
        else:
            result = api.encrypt(key(args[0]), data.encode(), policy, scheme=scheme, aes_key_bits=aes_bits)
        Path(output).write_bytes(result)
        print(f"Wrote {output}")
    else:
        ciphertext = Path(args[-1]).read_bytes()
        result = (api.decrypt_and_verify(key(args[0]), key(args[1]), ciphertext) if signed
                  else api.decrypt(key(args[0]), ciphertext))
        sys.stdout.flush()
        sys.stdout.buffer.write(b"Decrypted Buffer: " + result + b"\n")


def _run(command, args, options, signed, modern_signing):
    scheme = _SCHEMES[options.scheme]
    if command == "setup":
        if signed:
            api.setup_files_with_signing(*args, scheme=scheme, ml_dsa_parameter_set=options.ml_dsa,
                                         legacy_key_names=not modern_signing)
        else:
            api.setup_files(*args, scheme=scheme)
        if scheme == Scheme.COVERCRYPT and (not signed or modern_signing or options.ml_dsa is not None):
            print("CoverCrypt setup successful!")
    elif command == "genkey":
        api.generate_secret_key_file(*args, scheme=scheme)
        if scheme == Scheme.COVERCRYPT:
            print(f"User key generated successfully: {args[-1]}")
    elif command == "encrypt":
        if signed:
            api.encrypt_and_sign_file(*args, scheme=scheme, aes_key_bits=options.aes_bits,
                                      ml_dsa_parameter_set=options.ml_dsa)
        else:
            api.encrypt_file(*args, scheme=scheme, aes_key_bits=options.aes_bits)
        if options.aes_bits is not None or options.ml_dsa is not None:
            print(f"Wrote {args[-1]}")
    elif command == "decrypt":
        (api.decrypt_and_verify_file if signed else api.decrypt_file)(*args)
    elif command.endswith("_buffer"):
        _buffer_command(command, args, scheme, signed, options.aes_bits, options.ml_dsa)
    elif command in ("add_dimension", "add_attribute"):
        if scheme != Scheme.COVERCRYPT:
            raise ValueError("Authority growth requires --scheme covercrypt")
        if command == "add_dimension":
            master, dimension, output = args
            code = legacy.covercrypt_add_dimension(master, Path(dimension).read_text(encoding="utf-8"), output)
        else:
            code = legacy.covercrypt_add_attribute(*args)
        check_status(code, command)
        print("CoverCrypt authority updated successfully!")
    elif command == "test-buf":
        public, secret = (Path(path).read_bytes() for path in args)
        message = b"Hello, this is a test for Hybrid CP-ABE buffer encryption!"
        if api.decrypt(secret, api.encrypt(public, message, "admin and it", scheme=scheme)) != message:
            raise ValueError("Buffer test did not recover the original plaintext")
        print("Buffer encryption/decryption test PASSED!")
    else:
        print(legacy.get_version())


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = _parser()
    if not argv:
        parser.print_help()
        return 0
    if (len(argv) == 2 and (argv[0] == "help" or argv[1] in ("--help", "-h"))):
        command = (argv[1] if argv[0] == "help" else argv[0]).removeprefix("--")
        if command in _FILE_FIELDS or command in _POSITIONS or command in _ALIASES:
            print(_command_usage(command))
            return 0
    if argv == ["help"]:
        parser.print_help()
        return 0
    options = parser.parse_intermixed_args(argv)
    if options.test or options.version:
        if options.command or options.operands or options.test and options.version:
            parser.error("Use --test or --version separately")
        if options.test:
            from .selftest import main as run_selftest
            return run_selftest()
        print(legacy.get_version())
        return 0
    command, args, signed, modern_signing = _resolve(parser, options)
    env = {"HCPABE_COVERCRYPT_CONFIG": options.config, "HCPABE_COVERCRYPT_MODE": options.mode}
    previous = {name: os.environ.get(name) for name, value in env.items() if value is not None}
    try:
        for name in previous:
            os.environ[name] = env[name]
        _run(command, args, options, signed, modern_signing)
    except Exception as error:
        print(f"pq-cp-abe: {error}", file=sys.stderr)
        return 1
    finally:
        for name, value in previous.items():
            if value is None:
                del os.environ[name]
            else:
                os.environ[name] = value
    return 0


if __name__ == "__main__":
    sys.exit(main())
