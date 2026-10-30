# Build output layout

Keep generated output in the following subdirectories rather than writing files
directly into `build/`:

| Directory | Contents |
| --- | --- |
| `deps/<platform>/` | Staged dependency headers/libraries, ready marker and dependency build cache |
| `artifacts/<platform>/` | Project binaries, object files and platform tests |
| `logs/` | Build, test and diagnostic logs; older logs are under `logs/archive/` |
| `reports/covercrypt/` | CoverCrypt cost and KeyGen measurements |
| `reports/benchmarks/` | Local benchmark verification runs |
| `release/` | Packaged release archives |
| `tools/<name>/` | Downloaded development tools and their licenses |
| `tmp/` | Temporary test fixtures and scratch work |

Reusable source and diagnostic scripts belong in `scripts/diagnostics/` or
`tests/`, not in this generated-output directory. Scripts must create their
output subdirectories when needed.

`make deps -j8` owns dependency setup. Normal core builds reuse the existing
ready marker. `make clean` removes project core/object output;
`make deps-clean` removes dependency output for the current platform. Neither
command is intended to remove archived logs, reports or release packages.
