# Runnable integration examples

Four minimal, self-contained samples showing how to call the Herradura suite from
each supported language, plus one showing agent/tool integration via MCP. Each is a
single file with a comment block at the top giving its exact build/run command —
see the primary source of truth for the concepts these use in `docs/TUTORIAL.md`.

**Suggested order:**

1. **[`python/hello_herradura.py`](python/hello_herradura.py)** — start here. Python
   is the suite's reference implementation (the one the other language ports are
   checked against), and this example needs no build step: `python3
   docs/examples/python/hello_herradura.py`. Demonstrates an HKEX-GF key exchange
   plus an HSKE encrypt/decrypt round-trip.
2. **[`c/hello_herradura.c`](c/hello_herradura.c)** — the same walkthrough using the
   header-only `herradura.h` library (`#include`, no separate build/link step beyond
   `gcc -O2 -I../../.. hello_herradura.c -o hello_herradura`).
3. **[`go/hello_herradura.go`](go/hello_herradura.go)** — the same walkthrough again,
   using the `herradurakex/herradura` Go package (`go run
   docs/examples/go/hello_herradura.go` from the repo root).
4. **[`mcp/hello_herradura_mcp.py`](mcp/hello_herradura_mcp.py)** — read this last, once
   the CLI/library surface above is familiar. It drives `Mcp/herradura_mcp_server.py`
   over the MCP stdio transport (JSON-RPC 2.0) to complete an HKEX-GF exchange and an
   HPKS sign/verify round-trip as an *agent* would — i.e. by calling tools rather than
   library functions directly. Read `Mcp/README.md`'s trust-model section first if
   you're adapting this into a real agent integration.

All four are linked from `README.md`, `docs/TUTORIAL.md`, and `llms.txt`; this file
only adds an order and a one-line "why" per sample.
