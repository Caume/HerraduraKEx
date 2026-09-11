# Herradura MCP server (TODO #134)

`herradura_mcp_server.py` exposes the suite's Python CLI (`HerraduraCli/herradura.py`) as
MCP tools over stdio, so an agent (Claude Code or any other MCP client) can drive
`genpkey`, `pkey`, `kex`, `enc`, `dec`, `sign`, `verify`, `dgst` as tool calls instead of
shelling out itself.

**Implementation note:** this is a from-scratch, stdlib-only implementation of the MCP
stdio transport (newline-delimited JSON-RPC 2.0) — no `mcp` SDK, no pip dependency,
consistent with the zero-external-dependency convention followed everywhere else in this
repo (`CLAUDE.md`). It implements only what a tool-calling client needs
(`initialize`, `tools/list`, `tools/call`, `ping`) — not the full MCP spec (no resources,
prompts, sampling, or roots).

## Trust model — read this before wiring the server into an agent

1. Every tool operates **only** on file paths the caller explicitly supplies in that
   call's arguments. The server has no default key directory, no implicit "last
   generated key," and no state carried between calls.
2. `genpkey`/`kex`/`sign`/`enc` do write files (that's the point), but only to the exact
   `out` path given — never silently, never to a server-chosen location.
3. **Private-key file contents are never echoed back in a tool's text response.**
   Responses report success/failure, the CLI's own stdout/stderr, and the output file
   path. If an agent needs to inspect key material, that's a deliberate separate step
   outside this server, not something it does for you. This holds because `pkey`
   hard-codes `--pubout`: the CLI *can* print a private scalar (`pkey --text` writes it
   in hex to stdout), and the server does not expose that path.
   (`Mcp/test_server.py` checks this against `sign`, `dec` and `pkey`, in both the
   base64-PEM and hex shapes — TODO #287.)

   **One thing this does not say, and used to imply.** It previously read "never file
   bytes", which overstates it: a caller that directs a tool's output to stdout with
   `out: "-"` receives that output in the response, because responses carry the CLI's
   stdout. For `herradura_dgst` that is the documented way to get a hex digest back. For
   `herradura_dec` it means the **decrypted plaintext** lands in the response, and
   therefore in the agent's context. That is the caller's choice, not a leak — but it is
   a choice worth making deliberately, so it is pinned by a test rather than left to be
   discovered.
4. The server performs no network I/O and does not "phone home." Every tool call is
   exactly one local subprocess invocation of `HerraduraCli/herradura.py` — no new
   cryptographic code lives in the server itself.
5. The server adds **no sandboxing** beyond what the OS/agent harness already provides.
   Run it with the same file-system permissions you'd trust the CLI itself with:
   "the agent can call `herradura_sign`/`herradura_dec`" is exactly as much blast
   radius as "the agent can run the CLI directly," because that's what it does.

## Setup

No install step — it's a single stdlib-only script.

```bash
python3 Mcp/herradura_mcp_server.py
```

To wire it into Claude Code (or another MCP-capable client) as a stdio server, point
your client's MCP server config at this command. For Claude Code specifically, see the
[MCP server documentation](https://docs.claude.com/en/docs/claude-code/mcp) — the
relevant config entry is a `command`/`args` pair identical to the line above.

## Tools

| Tool | Wraps | Notes |
|---|---|---|
| `herradura_genpkey` | `genpkey` | `algo`, `out` required. |
| `herradura_pkey` | `pkey --pubout` | Extracts a public key. |
| `herradura_kex` | `kex` | HKEX-RNL is two-round; see the tool description. |
| `herradura_enc` | `enc` | `key` (symmetric) or `pubkey` (asymmetric). |
| `herradura_dec` | `dec` | |
| `herradura_sign` | `sign` | |
| `herradura_verify` | `verify` | Returns `verdict: VALID`/`INVALID` — an INVALID verdict is a normal result, not a tool error. |
| `herradura_dgst` | `dgst` | Omit `out` (or use `-`) to get hex back in the response instead of writing a file. |

Every tool's exact argument schema is in `TOOLS` in `herradura_mcp_server.py`
(`inputSchema`, JSON Schema); the current set of valid `algo` values per subcommand is
`spec/herradura-protocol-spec.json`'s `cli_subcommands` — see TODO #133.

## Testing

```bash
python3 Mcp/test_server.py                          # protocol + trust-model regression checks
python3 docs/examples/mcp/hello_herradura_mcp.py     # end-to-end HKEX-GF exchange + HPKS sign/verify
```
