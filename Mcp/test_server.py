#!/usr/bin/env python3
"""Smoke test for Mcp/herradura_mcp_server.py: speaks MCP over a subprocess
pipe (no `mcp` SDK -- see the server's docstring for why), drives
initialize -> tools/list -> tools/call, and exercises a full HKEX-GF key
exchange plus an HPKS sign/verify round-trip end-to-end through the server.

Usage: python3 Mcp/test_server.py
"""
import json
import os
import re
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


def _private_scalar_hex(priv_pem):
    """The private scalar as `pkey --text` would print it, or None.

    TODO #287.  The leak check needs the hex form as well as the base64 PEM
    body: `pkey --text` prints `private : <hex>` to stdout, and the server
    echoes stdout verbatim, so a future `text` passthrough would leak key
    material in a shape no base64-marker search would catch.  Obtained by
    running the CLI directly -- deliberately NOT through the server, since
    whether the server can reach this output is exactly what is being tested.
    """
    cli = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "HerraduraCli", "herradura.py")
    try:
        out = subprocess.run([sys.executable, cli, "pkey", "--in", priv_pem,
                              "--text", "--out", "-"],
                             capture_output=True, text=True, timeout=30).stdout
    except Exception:
        return None
    m = re.search(r"private\s*:\s*([0-9a-f]{16,})", out)
    return m.group(1) if m else None


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

        # ── enc / dec / dgst — TODO #287 ────────────────────────────────────
        # These three were named in the tools/list assertion above and never
        # CALLED, so five of eight tools were exercised end to end and the three
        # left out included `dec`, the one tool whose job is to turn a private
        # key plus a ciphertext into plaintext.
        hpke_priv = os.path.join(tmp, "hpke.pem")
        hpke_pub = os.path.join(tmp, "hpke_pub.pem")
        pt_path = os.path.join(tmp, "plain.txt")
        ct_path = os.path.join(tmp, "cipher.pem")
        rt_path = os.path.join(tmp, "roundtrip.txt")
        # Named PAYLOAD, not SECRET: it is the plaintext INPUT to an enc/dec
        # round-trip, not a credential.  CodeQL's
        # py/clear-text-storage-sensitive-data classifies a value as sensitive
        # from its identifier NAME, so the old name raised a high-severity
        # clear-text-storage alert on the f.write below -- on a fixed literal
        # written into a TemporaryDirectory that is deleted on block exit, and
        # written because herradura_enc takes --in <path> and so needs a file.
        # Renamed rather than dismissed: the alert was wrong, and so was the
        # name (TODO #287 follow-up).
        PAYLOAD = "mcp enc/dec round-trip payload\n"
        with open(pt_path, "w") as f:
            f.write(PAYLOAD)

        client.call_tool("herradura_genpkey", {"algo": "hpke", "out": hpke_priv})
        client.call_tool("herradura_pkey", {"in": hpke_priv, "out": hpke_pub})

        r = client.call_tool("herradura_enc", {"algo": "hpke", "pubkey": hpke_pub,
                                              "in": pt_path, "out": ct_path})
        ok &= check("enc", not r["isError"] and os.path.exists(ct_path))

        r_dec = client.call_tool("herradura_dec", {"algo": "hpke", "key": hpke_priv,
                                                  "in": ct_path, "out": rt_path})
        ok &= check("dec", not r_dec["isError"] and os.path.exists(rt_path))
        with open(rt_path, "rb") as f:
            recovered = f.read()
        # PREFIX, not equality: HPKE encrypts a fixed-width block, so the
        # recovered file is the plaintext zero-padded up to the block size (22
        # bytes in, 32 out at n=256).  Asserting equality here fails for a
        # reason that has nothing to do with the server.
        ok &= check("enc/dec round-trip recovers the plaintext",
                    recovered.startswith(PAYLOAD.encode())
                    and set(recovered[len(PAYLOAD):]) <= {0})

        dg_path = os.path.join(tmp, "digest.pem")
        r = client.call_tool("herradura_dgst", {"in": pt_path, "out": dg_path})
        ok &= check("dgst to a file", not r["isError"] and os.path.exists(dg_path))
        r = client.call_tool("herradura_dgst", {"in": pt_path})
        dg_text = "".join(c["text"] for c in r["content"])
        ok &= check("dgst with no out returns a hex digest in the response",
                    not r["isError"] and re.search(r"[0-9a-f]{64}", dg_text) is not None)

        # ── Trust model, claim 3: private key bytes never echoed ─────────────
        # Applied to THREE tools, not one.  It ran against `sign` alone until
        # TODO #287, which is the tool where a leak would matter least: `dec`
        # and `pkey` both read a private key, and `pkey`'s whole job is to
        # derive something publishable from it.
        def leaks(resp, marker):
            return any(marker in c["text"] for c in resp["content"])

        with open(hpks_priv) as f:
            hpks_body = f.read().splitlines()[1]   # a base64 body line, not the PEM header
        with open(hpke_priv) as f:
            hpke_body = f.read().splitlines()[1]

        r = client.call_tool("herradura_sign", {"algo": "hpks", "key": hpks_priv, "in": msg_path, "out": sig_path})
        ok &= check("sign: private key body never echoed", not leaks(r, hpks_body))
        ok &= check("dec: private key body never echoed", not leaks(r_dec, hpke_body))
        r = client.call_tool("herradura_pkey", {"in": hpke_priv, "out": hpke_pub})
        ok &= check("pkey: private key body never echoed", not leaks(r, hpke_body))

        # The CLI CAN print private material -- `pkey --text` writes the private
        # scalar in hex to stdout, and cli_result echoes stdout verbatim -- so
        # claim 3 holds because tool_pkey hard-codes --pubout and its schema is
        # additionalProperties:False.  That is a property by construction and
        # nothing tested it, so a later `text` passthrough would break the claim
        # while the base64-marker check above stayed green (the hex output
        # contains no PEM body line).  These two pin it.
        r = client.request("tools/call", {"name": "herradura_pkey",
                                          "arguments": {"in": hpke_priv, "out": hpke_pub,
                                                        "text": True}})
        rejected = ("error" in r) or r.get("result", {}).get("isError", False)
        ok &= check("pkey rejects a 'text' argument (schema is closed)", rejected)

        priv_hex = _private_scalar_hex(hpke_priv)
        r = client.call_tool("herradura_pkey", {"in": hpke_priv, "out": hpke_pub})
        ok &= check("pkey never echoes the private scalar in hex either",
                    priv_hex is None or not leaks(r, priv_hex))

        # ── Declared schemas must be ENFORCED, not just advertised ──────────
        # TODO #287.  Every input_schema carries "additionalProperties": False
        # and a "required" list, and both travel to the agent in tools/list.
        # Until #287 nothing checked them: an unknown argument was dropped in
        # silence, exit 0, artifact written, no mention in the response.
        #
        # The case that makes it matter is TODO #274's, one boundary further
        # out: misspell `aead` and the caller asked for authenticated
        # encryption and got confidentiality only.  At the CLI a human typed
        # the flag and can re-read it; here the caller is an LLM that generated
        # JSON from a schema promising violations are reported.
        r = client.request("tools/call", {"name": "herradura_enc",
                                          "arguments": {"algo": "hpke", "pubkey": hpke_pub,
                                                        "in": pt_path, "out": ct_path,
                                                        "totally_bogus_argument": "xyz"}})
        res = r.get("result", {})
        rejected = ("error" in r) or res.get("isError", False)
        named = "totally_bogus_argument" in "".join(c["text"] for c in res.get("content", []))
        ok &= check("an unknown argument is rejected, not silently dropped", rejected)
        ok &= check("...and the response names the offending argument", named)

        aead_ct = os.path.join(tmp, "aead.pem")
        r = client.request("tools/call", {"name": "herradura_enc",
                                          "arguments": {"algo": "hske-nla1", "key": hpke_priv,
                                                        "in": pt_path, "out": aead_ct,
                                                        "aeadd": True, "ad": "ctx"}})
        res = r.get("result", {})
        ok &= check("a misspelled 'aead' cannot silently drop authentication",
                    ("error" in r) or res.get("isError", False))
        ok &= check("...and no artifact is written for a rejected call",
                    not os.path.exists(aead_ct))

        r = client.request("tools/call", {"name": "herradura_dgst",
                                          "arguments": {"in": pt_path, "algo": "md5"}})
        res = r.get("result", {})
        ok &= check("an out-of-enum 'algo' is rejected",
                    ("error" in r) or res.get("isError", False))

        r = client.request("tools/call", {"name": "herradura_genpkey",
                                          "arguments": {"algo": "hpks"}})
        res = r.get("result", {})
        ok &= check("a missing required argument is reported as such",
                    ("error" in r) or res.get("isError", False))

        # ── What `out: "-"` means, pinned rather than assumed ───────────────
        # TODO #287.  cli_result echoes the CLI's stdout, and `dec --out -`
        # writes the PLAINTEXT to stdout -- so this call returns the decrypted
        # bytes in the tool response, where an agent's context will keep them.
        # That is legitimate (the caller asked for stdout, and `dgst`'s schema
        # documents exactly this pattern), but the trust model used to say
        # responses carry "never file bytes" flat out, which overstated it.
        # Pinned here so the behaviour is a decision and not a surprise: if a
        # future change starts REDACTING stdout, this check says so.
        r = client.call_tool("herradura_dec", {"algo": "hpke", "key": hpke_priv,
                                               "in": ct_path, "out": "-"})
        stdout_text = "".join(c["text"] for c in r["content"])
        ok &= check('dec with out="-" returns the plaintext in the response '
                    "(documented, not a leak)",
                    not r["isError"] and PAYLOAD.strip() in stdout_text)

        # ── Trust model, claim 2: writes ONLY to the given out path ──────────
        before = set(os.listdir(tmp))
        stray_out = os.path.join(tmp, "claim2.pem")
        client.call_tool("herradura_genpkey", {"algo": "hpks", "out": stray_out})
        after = set(os.listdir(tmp))
        ok &= check("genpkey writes only the caller's out path, nothing else",
                    after - before == {os.path.basename(stray_out)})

        # ── Trust model, claim 1: no state carried between calls ─────────────
        # A second call with NO key argument must fail rather than reuse the
        # previous one.  "No implicit last-generated key" is the claim.
        r = client.request("tools/call", {"name": "herradura_sign",
                                          "arguments": {"algo": "hpks", "in": msg_path,
                                                        "out": sig_path}})
        no_implicit = ("error" in r) or r.get("result", {}).get("isError", False)
        ok &= check("sign without a key does not reuse the last one (no server state)",
                    no_implicit)

    client.close()
    print()
    print("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
