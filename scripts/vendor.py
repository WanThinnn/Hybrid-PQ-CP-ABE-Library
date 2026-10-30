#!/usr/bin/env python3
"""Maintainer-only Git histories for ordinary vendored source (no submodules)."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


class VendorGit:
    def __init__(self, root=ROOT):
        self.root = Path(root).resolve()
        self.manifest = self.root / 'vendor/upstreams.json'
        self.sources = json.loads(self.manifest.read_text(encoding='utf-8'))
        self.git_dir = Path(self.run(['git', 'rev-parse', '--absolute-git-dir'], self.root).stdout.strip())

    @staticmethod
    def run(command, cwd, check=True):
        # Do not let a caller's Git override variables redirect a vendor action
        # into another index/worktree. All repository locations are explicit.
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                                text=True, encoding='utf-8', errors='replace')
        if check and result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f'Git exited {result.returncode}')
        return result

    def paths(self, name):
        if name not in self.sources or not re.fullmatch(r'[A-Za-z0-9_.-]+', name):
            raise ValueError(f'Unknown vendor: {name}')
        work = self.root / 'vendor' / name
        if work.is_symlink() or work.resolve().parent != (self.root / 'vendor').resolve():
            raise ValueError('Vendor worktree must be directly inside vendor/')
        if not work.is_dir():
            raise ValueError(f'Missing vendored source: {work}')
        if (work / '.git').exists():
            raise ValueError(f'{work}/.git already exists; refusing to replace embedded Git metadata')
        database = self.git_dir / 'vendors' / (name + '.git')
        return work, database

    def git(self, name, *arguments, check=True):
        work, database = self.paths(name)
        return self.run(['git', '--git-dir=' + str(database), '--work-tree=' + str(work),
                         *arguments], work, check)

    def ready(self, name):
        _, database = self.paths(name)
        if not database.is_dir() or self.git(name, 'config', '--get', 'vendor.initialized', check=False).stdout.strip() != 'true':
            raise RuntimeError(f'{name}: run python scripts/vendor.py init {name} first')

    def init(self, name):
        work, database = self.paths(name)
        if database.is_dir():
            if self.git(name, 'config', '--get', 'vendor.initialized', check=False).stdout.strip() == 'true':
                print(f'{name}: already initialized')
                return
            if self.git(name, 'rev-parse', '--verify', 'HEAD', check=False).returncode == 0:
                raise RuntimeError(f'{name}: incomplete metadata with an existing HEAD at {database}; inspect it before retrying')
        source = self.sources[name]
        if not re.fullmatch(r'[0-9a-f]{40}', source['commit']):
            raise ValueError(f'{name}: upstream commit must be a full SHA-1')
        print(f'{name}: initialize upstream {source["commit"][:12]}', flush=True)
        database.parent.mkdir(parents=True, exist_ok=True)
        self.run(['git', 'init', '--bare', str(database)], self.root)
        self.git(name, 'config', 'core.bare', 'false')
        self.git(name, 'config', 'core.worktree', str(work))
        self.git(name, 'config', 'core.autocrlf', 'input')
        self.git(name, 'config', 'core.safecrlf', 'false')
        self.git(name, 'config', 'commit.gpgsign', 'false')
        for key, fallback in (('user.name', 'Vendor snapshot'), ('user.email', 'vendor@localhost')):
            value = self.run(['git', 'config', '--get', key], self.root, check=False).stdout.strip() or fallback
            self.git(name, 'config', key, value)
        remote = self.git(name, 'remote', 'get-url', 'upstream', check=False)
        if remote.returncode:
            self.git(name, 'remote', 'add', 'upstream', source['url'])
        elif remote.stdout.strip() != source['url']:
            raise RuntimeError(f'{name}: upstream URL differs from the manifest')
        self.git(name, 'fetch', '--depth=1', 'upstream', source['commit'])
        self.git(name, 'update-ref', 'refs/heads/vendor-local', source['commit'])
        self.git(name, 'symbolic-ref', 'HEAD', 'refs/heads/vendor-local')
        # Set only the private index; never reset/checkout over the source tree.
        self.git(name, 'read-tree', source['commit'])
        self.git(name, 'add', '--all', '--', '.')
        # Some library upstreams ignore Cargo.lock, although this project tracks
        # it deliberately for reproducible --locked builds. Preserve those files
        # in the private integration history without importing build caches.
        prefix = f'vendor/{name}/'
        tracked = self.run(['git', 'ls-files', '-z', '--', prefix], self.root).stdout.split('\0')
        tracked = {path[len(prefix):] for path in tracked if path.startswith(prefix)}
        ignored = self.git(name, 'ls-files', '--others', '--ignored', '--exclude-standard', '-z').stdout.split('\0')
        preserve = sorted(tracked.intersection(ignored))
        for index in range(0, len(preserve), 64):
            self.git(name, 'add', '--force', '--', *preserve[index:index + 64])
        diff = self.git(name, 'diff', '--cached', '--quiet', check=False)
        if diff.returncode == 1:
            self.git(name, 'commit', '--quiet', '-m', 'Preserve vendored snapshot and local integration patches')
        elif diff.returncode:
            raise RuntimeError(diff.stderr)
        self.git(name, 'update-ref', 'refs/remotes/upstream/pinned', source['commit'])
        self.git(name, 'config', 'vendor.initialized', 'true')
        print(f'{name}: ready; source files unchanged', flush=True)

    def snapshot(self, name, message):
        self.ready(name)
        self.git(name, 'add', '--all', '--', '.')
        self.git(name, 'commit', '-m', message)

    def pull(self, name):
        self.ready(name)
        if self.git(name, 'status', '--porcelain').stdout.strip():
            raise RuntimeError(f'{name}: snapshot local changes before updating')
        response = self.git(name, 'ls-remote', '--symref', 'upstream', 'HEAD').stdout
        match = re.search(r'(?m)^ref:\s+(refs/heads/\S+)\s+HEAD$', response)
        if not match:
            raise RuntimeError(f'{name}: cannot discover the upstream default branch; use update --ref explicitly')
        ref = match[1]
        print(f'{name}: pulling {ref}', flush=True)
        self.update(name, ref)

    def update(self, name, ref):
        self.ready(name)
        if not ref or ref.startswith('-') or any(c.isspace() for c in ref):
            raise ValueError('Specify an upstream tag, branch or commit with --ref')
        if self.git(name, 'status', '--porcelain').stdout.strip():
            raise RuntimeError(f'{name}: snapshot local changes before updating')
        fetch = ['fetch']
        if self.git(name, 'rev-parse', '--is-shallow-repository').stdout.strip() == 'true':
            fetch.append('--unshallow')
        self.git(name, *fetch, 'upstream', ref)
        revision = self.git(name, 'rev-parse', 'FETCH_HEAD').stdout.strip()
        # A normal merge retains the integration commit. Conflicts are left for
        # the maintainer; neither the root repository nor its index is touched.
        self.git(name, 'merge', '--no-edit', revision)
        self.sources[name]['commit'] = revision
        self.manifest.write_text(json.dumps(self.sources, indent=2) + '\n', encoding='utf-8')
        self.git(name, 'update-ref', 'refs/remotes/upstream/pinned', revision)
        attribution = self.root / 'vendor' / name / 'UPSTREAM.md'
        if attribution.is_file():
            text = attribution.read_text(encoding='utf-8')
            text = re.sub(r'(?m)^(- Vendored commit:\s*`?)[0-9a-f]+(`?)[ \t]*$',
                          lambda m: m[1] + revision + m[2], text)
            attribution.write_text(text, encoding='utf-8')
            self.git(name, 'add', '--', 'UPSTREAM.md')
            if self.git(name, 'diff', '--cached', '--quiet', check=False).returncode == 1:
                self.git(name, 'commit', '--quiet', '-m', f'Record upstream revision {revision}')
        print(f'{name}: merged {revision}; review source changes, test and commit them in the main repository')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('init', 'status', 'pull'):
        sub = commands.add_parser(command)
        sub.add_argument('name', nargs='?', default='all')
    snapshot = commands.add_parser('snapshot')
    snapshot.add_argument('name')
    snapshot.add_argument('-m', '--message', required=True)
    update = commands.add_parser('update')
    update.add_argument('name')
    update.add_argument('--ref', required=True)
    passthrough = commands.add_parser('git', help='Run an explicit Git command scoped to one vendor')
    passthrough.add_argument('name')
    passthrough.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    vendors = VendorGit()
    names = list(vendors.sources) if getattr(args, 'name', None) == 'all' else [args.name]
    for name in names:
        if args.command == 'init':
            vendors.init(name)
        elif args.command == 'status':
            vendors.ready(name)
            print(f'[{name}]')
            print(vendors.git(name, 'status', '--short', '--branch').stdout, end='')
        elif args.command == 'snapshot':
            vendors.snapshot(name, args.message)
        elif args.command == 'pull':
            vendors.pull(name)
        elif args.command == 'update':
            vendors.update(name, args.ref)
        else:
            vendors.ready(name)
            if not args.arguments:
                parser.error('git requires a command, e.g. git cover_crypt status')
            result = vendors.git(name, *args.arguments)
            print(result.stdout, end='')
            print(result.stderr, end='', file=sys.stderr)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError) as error:
        print(f'vendor: {error}', file=sys.stderr)
        sys.exit(1)
