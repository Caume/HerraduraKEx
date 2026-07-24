"""
hello_herradura_mcp.py — Minimal MCP integration example for the Herradura suite.

Run from the repo root:
    python3 docs/examples/mcp/hello_herradura_mcp.py

Shows an agent driving Mcp/herradura_mcp_server.py over the MCP stdio
transport (JSON-RPC 2.0, one message per line) to complete, end-to-end:
  1. An HKEX-GF key exchange between two parties ("Alice" and "Bob").
  2. An HPKS sign/verify round-trip.

No `mcp` SDK is used here (nor by the server) -- see Mcp/herradura_mcp_server.py's
docstring for why (this project's zero-external-dependency convention). The
~30-line McpClient below is the entire client-side protocol surface needed to
drive a tool-calling MCP server: initialize, tools/list, tools/call.

Read Mcp/README.md's trust-model section before wiring this server into a real
agent -- every tool call here operates on file paths this script chooses
explicitly; the server never invents or reuses a path on its own.
"""
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
SERVER = os.path.join(REPO, "Mcp", "herradura_mcp_server.py")


class McpClient:
    """The minimal client-side surface of the MCP stdio transport."""

    def __init__(self, server_path):
        self.proc = subprocess.Popen(
            [sys.executable, server_path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
            text=True, bufsize=1,
        )
        self._id = 0

    def request(self, method, params=None):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def call_tool(self, name, arguments):
        resp = self.request("tools/call", {"name": name, "arguments": arguments})
        if "error" in resp:
            raise RuntimeError(f"{name} failed: {resp['error']}")
        result = resp["result"]
        if result.get("isError"):
            raise RuntimeError(f"{name} reported an error: {result['content']}")
        return result

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=5)


def show(label, result):
    print(f"-- {label} --")
    for block in result["content"]:
        print(block["text"])
    print()


# ── Connect and handshake ────────────────────────────────────────────────────
client = McpClient(SERVER)
client.request("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "hello_herradura_mcp", "version": "1"}})
client.notify("notifications/initialized")

with tempfile.TemporaryDirectory() as tmp:
    def p(name):
        return os.path.join(tmp, name)

    # ── HKEX-GF key exchange ────────────────────────────────────────────────
    print("=== HKEX-GF key exchange, driven entirely through MCP tool calls ===\n")

    show("Alice: genpkey", client.call_tool("herradura_genpkey", {"algo": "hkex-gf", "out": p("alice.pem")}))
    show("Bob: genpkey", client.call_tool("herradura_genpkey", {"algo": "hkex-gf", "out": p("bob.pem")}))

    show("Alice: pkey (publish public key)",
         client.call_tool("herradura_pkey", {"in": p("alice.pem"), "out": p("alice_pub.pem")}))
    show("Bob: pkey (publish public key)",
         client.call_tool("herradura_pkey", {"in": p("bob.pem"), "out": p("bob_pub.pem")}))

    show("Alice: kex (derive shared secret using Bob's public key)",
         client.call_tool("herradura_kex", {"algo": "hkex-gf", "our": p("alice.pem"),
                                             "their": p("bob_pub.pem"), "out": p("alice_sk.pem")}))
    show("Bob: kex (derive shared secret using Alice's public key)",
         client.call_tool("herradura_kex", {"algo": "hkex-gf", "our": p("bob.pem"),
                                             "their": p("alice_pub.pem"), "out": p("bob_sk.pem")}))

    with open(p("alice_sk.pem")) as f:
        alice_sk = f.read()
    with open(p("bob_sk.pem")) as f:
        bob_sk = f.read()
    print(f"Alice's and Bob's derived session keys match: {alice_sk == bob_sk}\n")

    # ── HPKS sign/verify ─────────────────────────────────────────────────────
    print("=== HPKS sign/verify, driven entirely through MCP tool calls ===\n")

    client.call_tool("herradura_genpkey", {"algo": "hpks", "out": p("signer.pem")})
    client.call_tool("herradura_pkey", {"in": p("signer.pem"), "out": p("signer_pub.pem")})

    with open(p("message.txt"), "w") as f:
        f.write("Two agents agreeing on a shared secret and signing a message, "
                "with a third agent never seeing key material in the tool-call log.\n")

    show("sign", client.call_tool("herradura_sign", {"algo": "hpks", "key": p("signer.pem"),
                                                       "in": p("message.txt"), "out": p("message.sig.pem")}))
    show("verify (correct message)",
         client.call_tool("herradura_verify", {"algo": "hpks", "pubkey": p("signer_pub.pem"),
                                                "in": p("message.txt"), "sig": p("message.sig.pem")}))

client.close()
