#!/usr/bin/env python3
"""Smoke test for Mcp/herradura_mcp_server.py: speaks MCP over a subprocess
pipe (no `mcp` SDK -- see the server's docstring for why), drives
initialize -> tools/list -> tools/call, and exercises a full HKEX-GF key
exchange plus an HPKS sign/verify round-trip end-to-end through the server.

Usage: python3 Mcp/test_server.py
"""
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(REPO, "Mcp", "herradura_mcp_server.py")


class McpClient:
    def __init__(self, server_path):
        self.proc = subprocess.Popen(
            [sys.executable, server_path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
            text=True, bufsize=1,
        )
        self._id = 0

    def _send(self, msg):
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def request(self, method, params=None):
        self._id += 1
        self._send({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}})
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed stdout unexpectedly")
        return json.loads(line)

    def notify(self, method, params=None):
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def call_tool(self, name, arguments):
        resp = self.request("tools/call", {"name": name, "arguments": arguments})
        if "error" in resp:
            raise RuntimeError(f"{name}: {resp['error']}")
        return resp["result"]

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=5)


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"{status} {label}")
    return condition


def main():
    ok = True
    client = McpClient(SERVER)

    init = client.request("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                          "clientInfo": {"name": "test_server.py", "version": "0"}})
    ok &= check("initialize", init.get("result", {}).get("serverInfo", {}).get("name") == "herradura-mcp")
    client.notify("notifications/initialized")

    tools = client.request("tools/list")
    tool_names = {t["name"] for t in tools["result"]["tools"]}
    expected = {"herradura_genpkey", "herradura_pkey", "herradura_kex", "herradura_enc",
                "herradura_dec", "herradura_sign", "herradura_verify", "herradura_dgst"}
    ok &= check("tools/list exposes all 8 tools", expected <= tool_names)

    with tempfile.TemporaryDirectory() as tmp:
        alice_priv = os.path.join(tmp, "alice.pem")
        bob_priv = os.path.join(tmp, "bob.pem")
        alice_pub = os.path.join(tmp, "alice_pub.pem")
        bob_pub = os.path.join(tmp, "bob_pub.pem")
        alice_sk = os.path.join(tmp, "alice_sk.pem")
        bob_sk = os.path.join(tmp, "bob_sk.pem")

        r = client.call_tool("herradura_genpkey", {"algo": "hkex-gf", "out": alice_priv})
        ok &= check("genpkey alice", not r["isError"] and os.path.exists(alice_priv))
        r = client.call_tool("herradura_genpkey", {"algo": "hkex-gf", "out": bob_priv})
        ok &= check("genpkey bob", not r["isError"] and os.path.exists(bob_priv))

        r = client.call_tool("herradura_pkey", {"in": alice_priv, "out": alice_pub})
        ok &= check("pkey alice pubout", not r["isError"] and os.path.exists(alice_pub))
        r = client.call_tool("herradura_pkey", {"in": bob_priv, "out": bob_pub})
        ok &= check("pkey bob pubout", not r["isError"] and os.path.exists(bob_pub))

        r = client.call_tool("herradura_kex", {"algo": "hkex-gf", "our": alice_priv, "their": bob_pub, "out": alice_sk})
        ok &= check("kex alice", not r["isError"] and os.path.exists(alice_sk))
        r = client.call_tool("herradura_kex", {"algo": "hkex-gf", "our": bob_priv, "their": alice_pub, "out": bob_sk})
        ok &= check("kex bob", not r["isError"] and os.path.exists(bob_sk))

        with open(alice_sk) as f:
            alice_sk_text = f.read()
        with open(bob_sk) as f:
            bob_sk_text = f.read()
        ok &= check("both sides derive the same session key", alice_sk_text == bob_sk_text)

        # HPKS sign/verify round-trip
        hpks_priv = os.path.join(tmp, "signer.pem")
        hpks_pub = os.path.join(tmp, "signer_pub.pem")
        msg_path = os.path.join(tmp, "message.txt")
        sig_path = os.path.join(tmp, "message.sig.pem")
        with open(msg_path, "w") as f:
            f.write("hello from the MCP smoke test\n")

        client.call_tool("herradura_genpkey", {"algo": "hpks", "out": hpks_priv})
        client.call_tool("herradura_pkey", {"in": hpks_priv, "out": hpks_pub})
        r = client.call_tool("herradura_sign", {"algo": "hpks", "key": hpks_priv, "in": msg_path, "out": sig_path})
        ok &= check("sign", not r["isError"] and os.path.exists(sig_path))

        r = client.call_tool("herradura_verify", {"algo": "hpks", "pubkey": hpks_pub, "in": msg_path, "sig": sig_path})
        text = r["content"][0]["text"]
        ok &= check("verify correct message -> VALID", "verdict: VALID" in text and not r["isError"])

        with open(msg_path, "a") as f:
            f.write("tampered\n")
        r = client.call_tool("herradura_verify", {"algo": "hpks", "pubkey": hpks_pub, "in": msg_path, "sig": sig_path})
        text = r["content"][0]["text"]
        ok &= check("verify tampered message -> INVALID (not a tool error)",
                    "verdict: INVALID" in text and not r["isError"])

        # Trust-model check: private key bytes must never appear in a response.
        with open(hpks_priv) as f:
            priv_bytes_marker = f.read().splitlines()[1]  # a base64 body line, not the PEM header
        r = client.call_tool("herradura_sign", {"algo": "hpks", "key": hpks_priv, "in": msg_path, "out": sig_path})
        leaked = any(priv_bytes_marker in c["text"] for c in r["content"])
        ok &= check("private key body never echoed in a tool response", not leaked)

    client.close()
    print()
    print("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
