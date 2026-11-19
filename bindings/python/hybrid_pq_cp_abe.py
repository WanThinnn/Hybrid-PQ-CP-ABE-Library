"""Backward-compatible import and CLI entrypoint. Prefer `import pq_cp_abe`."""
from pq_cp_abe import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy
    runpy.run_module("pq_cp_abe", run_name="__main__")
