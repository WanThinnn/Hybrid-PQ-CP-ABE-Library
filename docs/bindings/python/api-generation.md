---
icon: lucide/file-cog
---

# Generate Python class/function documentation

The SDK already exposes type annotations, a `py.typed` marker and some docstrings. API documentation generators can list its modules, public classes, methods and signatures automatically. **They cannot invent missing parameter semantics or security guarantees:** improve the docstrings and keep the curated [API reference](api.md) for behavior and caveats.

## Public Python API with pdoc

Official documentation: [pdoc.dev](https://pdoc.dev/).

~~~sh
python -m pip install pdoc==16.0.0
python -m pdoc -t docs/bindings/python/pdoc --no-show-source --no-browser -p 8080 bindings/python/pq_cp_abe "!^pq_cp_abe\."
~~~

Run this from the repository root, then open
[the Python API reference](http://localhost:8080/pq_cp_abe.html). If an
unfiltered pdoc server is already using port 8080, stop it in its terminal
before running this command.

The template shows the package's high-level classes, typed results, enums,
errors, and functional API. It hides the compatibility wrappers, native
handle, and implementation submodules. Python imports retain their original
behavior.

To generate static HTML, replace `--no-browser -p 8080` with
`-o build/docs/python-api`.

`pdoc` imports/inspects the package, reads signatures, type hints, module and class docstrings, and renders navigable HTML. It is the quickest choice for **SDK API documentation without a large documentation site**.

**Important for this repository:** importing `pq_cp_abe` loads `_native.py`, which requires a compatible native DLL/SO/DYLIB. Run pdoc in an environment where the wheel/native library works. Do not assume docs generation works on machines that only have the Python source.

## For a complete documentation website: MkDocs + mkdocstrings

Official docs: [MkDocs](https://www.mkdocs.org/) and [mkdocstrings-python](https://mkdocstrings.github.io/python/).

~~~sh
python -m pip install mkdocs-material "mkdocstrings[python]"
~~~

Example `mkdocs.yml` (**proposal; not created or enabled by this guide**):

~~~yaml
site_name: PQ-CP-ABE SDK
docs_dir: docs
theme:
  name: material
plugins:
  - search
  - mkdocstrings:
      handlers:
        python:
          paths: [bindings/python]
~~~

Example Markdown API page (**proposal**):

~~~md
# Python API

::: pq_cp_abe.pq_cp_abe.PqCpAbe

::: pq_cp_abe.abe.covercrypt.CoverCryptABE

::: pq_cp_abe.api.functional
~~~

Run `mkdocs serve` locally or `mkdocs build` for static HTML after creating the configuration. MkDocs is a good future choice if Python, WASM, CLI and architecture documentation will share one published site.

## Alternative: Sphinx autodoc

[Sphinx autodoc](https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html) and [apidoc](https://www.sphinx-doc.org/en/master/usage/extensions/apidoc.html) support full module/class/function reference generation, Python cross-references and extensive extension workflows. Choose them if the project grows into a large reference manual or needs advanced API cross-linking.

## Suggested documentation conventions

- Use Google-style docstrings consistently for public classes/functions: purpose, `Args`, `Returns`, `Raises`, important security caveats.
- Document default scheme, KEM mode, accepted parameter sets, key encoding and who owns secret material.
- Mark internals (`_native`, internal runtime helpers) as implementation details rather than product APIs.
- Add docs generation to CI only after confirming native library loading works on the chosen runner.
- Publish generated HTML as an artifact/site, **not** directly inside README or `src/`; keep examples in [Python guide](README.md) and [API reference](api.md) manually reviewed.
