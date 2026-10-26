# TKN20 C bridge

Project-owned Go/C bridge for Cloudflare CIRCL TKN20.

The upstream CIRCL source is vendored separately in `vendor/circl/` and pinned to v1.6.4. The local `go.mod` uses a `replace` directive so builds use that vendored source instead of downloading CIRCL again.
