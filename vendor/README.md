# Maintainer-managed vendored source

These directories contain ordinary tracked source, not Git submodules. A normal
clone of the main repository already has everything needed by `make deps`.
Upstream URLs and the exact imported commits are pinned in `upstreams.json`.
CIRCL is the complete `cloudflare/circl` repository: its TKN20 implementation
also imports packages outside the upstream `abe/` directory.

The maintainer's private Git databases live under the main repository's
`.git/vendors/<name>.git`. They retain upstream history plus a local integration
branch. There is intentionally no `.git` marker inside a source directory, so
the main repository continues to discover new vendor files normally.

Initialize these databases once on the maintainer's machine (requires Git,
Python 3 and network access):

```sh
python scripts/vendor.py init
python scripts/vendor.py status
```

Initialization fetches the pinned upstream commit and records the existing
vendored snapshot and local patches in a private commit. It does not checkout,
reset or replace any source file, change the main repository's index, or push
anything. Running init again leaves an initialized database alone.

To inspect one vendor using normal Git commands scoped to its private database:

```sh
python scripts/vendor.py git cover_crypt status
python scripts/vendor.py git cover_crypt log --oneline -5
python scripts/vendor.py git cover_crypt remote -v
```

Do not use plain `git pull` after changing into a vendor directory: with this
layout Git discovers the **main** repository. Use the helper instead.

## Update workflow

To pull the default upstream branch automatically for every initialized vendor:

```sh
python scripts/vendor.py pull
```

Or pull just one:

```sh
python scripts/vendor.py pull cover_crypt
```

This discovers each repository's default branch from upstream HEAD, then fetches
and merges it into the local integration branch. Local commits are retained.
It stops at the first dirty worktree or merge conflict; earlier successful
merges remain for review. Nothing is automatically pushed. This is a
maintainer command; builds continue to consume the checked-in source.

For controlled updates to a particular release, use the explicit workflow below.

1. If local integration code changed, record it in the private vendor history:

   ```sh
   python scripts/vendor.py snapshot cover_crypt -m "Describe local integration changes"
   ```

2. Merge an explicit upstream tag, branch or commit:

   ```sh
   python scripts/vendor.py update cover_crypt --ref <upstream-tag-or-commit>
   ```

   The helper refuses dirty vendor worktrees. The first update expands the
   shallow initial history. A normal Git merge retains the integration commit;
   conflicts are left for the maintainer to resolve. To abort that merge:

   ```sh
   python scripts/vendor.py git cover_crypt merge --abort
   ```

   After a successful update, the helper records the new upstream SHA in
   `upstreams.json` and the vendor's `UPSTREAM.md`. Review any release/version
   labels in that attribution file as part of the update.

3. Review the main repository's vendor diff, then rebuild and test:

   ```sh
   git diff -- vendor
   make deps -j8
   make -j8
   make test -j8
   ```

4. Commit the reviewed source and manifest in the **main** repository, then push
   that main-repository commit using your normal workflow. The private
   `.git/vendors/` databases are local maintenance state, not files to add.

The helper never pushes to the five upstream repositories. Other contributors
and CI do not need to initialize these databases.
