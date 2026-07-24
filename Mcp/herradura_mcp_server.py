#!/usr/bin/env python3
"""Herradura MCP server (TODO #134) -- exposes the suite's Python CLI
(HerraduraCli/herradura.py) as MCP tools over stdio, so an agent can drive
genpkey/pkey/kex/enc/dec/sign/verify/dgst without shelling out itself.

No external dependencies (no `mcp` SDK, no pip package) -- consistent with
this project's zero-dependency convention everywhere else (see CLAUDE.md).
This is a minimal, from-scratch implementation of the MCP stdio transport:
newline-delimited JSON-RPC 2.0 messages on stdin/stdout, implementing just
the methods a tool-calling client needs (initialize, tools/list, tools/call,
ping) -- not the full spec (no resources, prompts, sampling, roots).

── Trust model (read before wiring this into an agent) ─────────────────────

  1. Every tool operates ONLY on file paths the caller explicitly supplies
     in that call's arguments. The server has no default key directory, no
     implicit "last generated key", and no state carried between calls.
  2. genpkey/kex/sign/enc DO write files (that's the point), but only to the
     exact --out path given -- never silently, never to a server-chosen
     location.
  3. Private-key file *contents* are never echoed back in a tool's text
     response. Responses report success/failure, the CLI's stdout/stderr,
     and the output path -- never file bytes. If an agent needs to inspect
     key material, that's a deliberate separate step outside this server
     (e.g. its own file-read tool), not something this server does for you.
  4. This server performs no network I/O and does not "phone home". Every
     tool call is exactly one local subprocess invocation of
     HerraduraCli/herradura.py, already shipped and tested in this repo --
     no new cryptographic code lives here.
  5. This server adds no sandboxing beyond what the OS/agent harness already
     provides. Run it with the same file-system permissions you'd trust the
     CLI itself with, and treat "the agent can call genpkey/sign/dec" as
     equivalent in blast radius to "the agent can run this CLI directly" --
     because that's exactly what it does.

Usage:
    python3 Mcp/herradura_mcp_server.py
(reads JSON-RPC requests from stdin, one per line, writes responses to
stdout, one per line; logs go to stderr so they never corrupt the stdio
transport.)
"""
import json
import subprocess
import sys
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERRADURA_PY = os.path.join(REPO, "HerraduraCli", "herradura.py")
PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "herradura-mcp"
SERVER_VERSION = "1.0.0"
SUBPROCESS_TIMEOUT = 30


def log(msg):
    print(f"[herradura-mcp] {msg}", file=sys.stderr, flush=True)


# ── CLI invocation ──────────────────────────────────────────────────────────

def run_cli(args):
    """Run `python3 HerraduraCli/herradura.py <args>`, return
    (ok: bool, stdout: str, stderr: str, returncode: int)."""
    cmd = [sys.executable, HERRADURA_PY] + args
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, "", f"timed out after {SUBPROCESS_TIMEOUT}s", -1
    return proc.returncode == 0, proc.stdout, proc.stderr, proc.returncode


def cli_result(args, out_path=None):
    """Standard tool-result shape for a CLI invocation: reports success,
    the CLI's own stdout/stderr, and (never) file contents."""
    ok, out, err, rc = run_cli(args)
    lines = [f"command: herradura {' '.join(args)}", f"exit_code: {rc}"]
    if out.strip():
        lines.append(f"stdout:\n{out.strip()}")
    if err.strip():
        lines.append(f"stderr:\n{err.strip()}")
    if ok and out_path:
        lines.append(f"output_path: {out_path}")
    text = "\n".join(lines)
    return {"content": [{"type": "text", "text": text}], "isError": not ok}


# ── Tool implementations ─────────────────────────────────────────────────────
# Every tool takes explicit file-path arguments only -- see trust model above.

def tool_genpkey(a):
    args = ["genpkey", "--algo", a["algo"], "--out", a["out"]]
    if "bits" in a and a["bits"] is not None:
        args += ["--bits", str(a["bits"])]
    return cli_result(args, out_path=a["out"])


def tool_pkey(a):
    args = ["pkey", "--in", a["in"], "--pubout", "--out", a["out"]]
    return cli_result(args, out_path=a["out"])


def tool_kex(a):
    args = ["kex", "--algo", a["algo"], "--our", a["our"], "--their", a["their"], "--out", a["out"]]
    if a.get("kdf"):
        args += ["--kdf", a["kdf"]]
    return cli_result(args, out_path=a["out"])


def tool_enc(a):
    args = ["enc", "--algo", a["algo"], "--in", a["in"], "--out", a["out"]]
    if a.get("key"):
        args += ["--key", a["key"]]
    if a.get("pubkey"):
        args += ["--pubkey", a["pubkey"]]
    if a.get("aead"):
        args += ["--aead"]
    if a.get("ad"):
        args += ["--ad", a["ad"]]
    return cli_result(args, out_path=a["out"])


def tool_dec(a):
    args = ["dec", "--algo", a["algo"], "--key", a["key"], "--in", a["in"], "--out", a["out"]]
    if a.get("ad"):
        args += ["--ad", a["ad"]]
    return cli_result(args, out_path=a["out"])


def tool_sign(a):
    args = ["sign", "--algo", a["algo"], "--key", a["key"], "--in", a["in"], "--out", a["out"]]
    if a.get("digest"):
        args += ["--digest", a["digest"]]
    if a.get("ring"):
        args += ["--ring", a["ring"]]
    return cli_result(args, out_path=a["out"])


def tool_verify(a):
    args = ["verify", "--algo", a["algo"], "--in", a["in"], "--sig", a["sig"]]
    if a.get("pubkey"):
        args += ["--pubkey", a["pubkey"]]
    if a.get("ring"):
        args += ["--ring", a["ring"]]
    if a.get("digest"):
        args += ["--digest", a["digest"]]
    # verify's own exit code (0=valid, 1=invalid) is the real answer here --
    # don't fold "signature didn't verify" into isError, that's a normal
    # negative result, not a tool failure.
    ok, out, err, rc = run_cli(args)
    verdict = "VALID" if rc == 0 else "INVALID"
    lines = [f"command: herradura {' '.join(args)}", f"exit_code: {rc}", f"verdict: {verdict}"]
    if out.strip():
        lines.append(f"stdout:\n{out.strip()}")
    if err.strip():
        lines.append(f"stderr:\n{err.strip()}")
    return {"content": [{"type": "text", "text": "\n".join(lines)}], "isError": rc not in (0, 1)}


def tool_dgst(a):
    out = a.get("out", "-")
    args = ["dgst", "--in", a["in"], "--out", out]
    if a.get("algo"):
        args += ["--algo", a["algo"]]
    return cli_result(args, out_path=(out if out != "-" else None))


TOOLS = {
    "herradura_genpkey": dict(
        fn=tool_genpkey,
        description="Generate a private key PEM file. Writes ONLY to the caller-supplied --out "
                    "path; never picks a path itself. See server trust model note 1-2.",
        input_schema={
            "type": "object", "required": ["algo", "out"], "additionalProperties": False,
            "properties": {
                "algo": {"type": "string", "description": "See spec/herradura-protocol-spec.json "
                          "cli_subcommands.genpkey.algos for the full, current list."},
                "out": {"type": "string", "description": "Output PEM file path."},
                "bits": {"type": "integer", "description": "Key size in bits (default 256; Stern: matrix dimension N)."},
            },
        }),
    "herradura_pkey": dict(
        fn=tool_pkey,
        description="Extract the public key from a private key PEM file.",
        input_schema={
            "type": "object", "required": ["in", "out"], "additionalProperties": False,
            "properties": {
                "in": {"type": "string", "description": "Input private-key PEM path."},
                "out": {"type": "string", "description": "Output public-key PEM path."},
            },
        }),
    "herradura_kex": dict(
        fn=tool_kex,
        description="Run one side of a key exchange (HKEX-GF or HKEX-RNL). HKEX-RNL is two-round: "
                    "the responder runs first with --their=<initiator_pub.pem>, producing a response "
                    "PEM; the initiator then runs with --their=<response.pem> to derive the same key.",
        input_schema={
            "type": "object", "required": ["algo", "our", "their", "out"], "additionalProperties": False,
            "properties": {
                "algo": {"type": "string", "enum": ["hkex-gf", "hkex-rnl"]},
                "our": {"type": "string", "description": "This party's own private-key PEM path."},
                "their": {"type": "string", "description": "The counterparty's public-key (or, for "
                          "HKEX-RNL round 2, response) PEM path."},
                "out": {"type": "string", "description": "Output path for the derived session key "
                        "(or, for HKEX-RNL round 1, the response PEM)."},
                "kdf": {"type": "string", "enum": ["none", "hfscx-256"], "description": "Both sides "
                        "must use the same value."},
            },
        }),
    "herradura_enc": dict(
        fn=tool_enc,
        description="Encrypt a file. Symmetric algorithms take --key (a session-key PEM from "
                    "herradura_kex); asymmetric algorithms take --pubkey.",
        input_schema={
            "type": "object", "required": ["algo", "in", "out"], "additionalProperties": False,
            "properties": {
                "algo": {"type": "string"},
                "key": {"type": "string", "description": "Session-key PEM path (symmetric algos)."},
                "pubkey": {"type": "string", "description": "Recipient public-key PEM path (asymmetric algos)."},
                "in": {"type": "string"}, "out": {"type": "string"},
                "aead": {"type": "boolean", "description": "hske-nla1 only: authenticated encryption."},
                "ad": {"type": "string", "description": "Associated data (requires aead=true)."},
            },
        }),
    "herradura_dec": dict(
        fn=tool_dec,
        description="Decrypt a file produced by herradura_enc.",
        input_schema={
            "type": "object", "required": ["algo", "key", "in", "out"], "additionalProperties": False,
            "properties": {
                "algo": {"type": "string"}, "key": {"type": "string", "description": "Session-key PEM "
                          "(symmetric) or private-key PEM (asymmetric)."},
                "in": {"type": "string"}, "out": {"type": "string"},
                "ad": {"type": "string", "description": "Must match the --ad used at encryption time."},
            },
        }),
    "herradura_sign": dict(
        fn=tool_sign,
        description="Sign a file with a private key, producing a signature (or ZKP proof) PEM.",
        input_schema={
            "type": "object", "required": ["algo", "key", "in", "out"], "additionalProperties": False,
            "properties": {
                "algo": {"type": "string"}, "key": {"type": "string"}, "in": {"type": "string"},
                "out": {"type": "string"},
                "digest": {"type": "string", "enum": ["none", "hfscx-256"]},
                "ring": {"type": "string", "description": "hpks-ring only: comma-separated member "
                          "public-key PEM paths."},
            },
        }),
    "herradura_verify": dict(
        fn=tool_verify,
        description="Verify a signature (or ZKP proof) against a message file. Returns "
                    "verdict=VALID/INVALID -- an INVALID verdict is a normal result, not a tool error.",
        input_schema={
            "type": "object", "required": ["algo", "in", "sig"], "additionalProperties": False,
            "properties": {
                "algo": {"type": "string"}, "pubkey": {"type": "string"}, "in": {"type": "string"},
                "sig": {"type": "string"},
                "digest": {"type": "string", "enum": ["none", "hfscx-256"], "description": "Must "
                          "match the value used when signing."},
                "ring": {"type": "string", "description": "hpks-ring only: comma-separated member "
                          "public-key PEM paths."},
            },
        }),
    "herradura_dgst": dict(
        fn=tool_dgst,
        description="Compute a digest (default HFSCX-256) of a file.",
        input_schema={
            "type": "object", "required": ["in"], "additionalProperties": False,
            "properties": {
                "in": {"type": "string"},
                "out": {"type": "string", "description": "Omit (or '-') to return hex in the tool "
                        "response instead of writing a PEM file."},
                "algo": {"type": "string", "enum": ["hfscx-256", "hfscx-256-ds"]},
            },
        }),
}


# ── JSON-RPC / MCP stdio transport ───────────────────────────────────────────

def make_response(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def make_error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def handle_request(msg):
    method = msg.get("method")
    req_id = msg.get("id")
    is_notification = "id" not in msg

    if method == "initialize":
        result = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }
        return None if is_notification else make_response(req_id, result)

    if method == "notifications/initialized":
        return None  # no response to notifications

    if method == "ping":
        return None if is_notification else make_response(req_id, {})

    if method == "tools/list":
        tools = [
            {"name": name, "description": spec["description"], "inputSchema": spec["input_schema"]}
            for name, spec in TOOLS.items()
        ]
        return None if is_notification else make_response(req_id, {"tools": tools})

    if method == "tools/call":
        params = msg.get("params", {})
        name = params.get("name")
        arguments = params.get("arguments", {}) or {}
        if name not in TOOLS:
            if is_notification:
                return None
            return make_error(req_id, -32602, f"unknown tool: {name}")
        try:
            result = TOOLS[name]["fn"](arguments)
        except KeyError as e:
            result = {"content": [{"type": "text", "text": f"missing required argument: {e}"}], "isError": True}
        except Exception as e:
            log(f"tool {name} raised: {e!r}")
            result = {"content": [{"type": "text", "text": f"internal error: {e}"}], "isError": True}
        return None if is_notification else make_response(req_id, result)

    if is_notification:
        return None
    return make_error(req_id, -32601, f"method not found: {method}")


def main():
    log(f"{SERVER_NAME} v{SERVER_VERSION} starting (wraps {HERRADURA_PY}); reading stdio")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            print(json.dumps(make_error(None, -32700, f"parse error: {e}")), flush=True)
            continue
        try:
            response = handle_request(msg)
        except Exception as e:
            log(f"unhandled error: {e!r}")
            response = make_error(msg.get("id"), -32603, f"internal error: {e}")
        if response is not None:
            print(json.dumps(response), flush=True)
    log("stdin closed, exiting")


if __name__ == "__main__":
    main()
