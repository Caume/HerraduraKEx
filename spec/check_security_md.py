#!/usr/bin/env python3
"""Cross-references spec/herradura-protocol-spec.json against SECURITY.md's
protocol table (TODO #238 Part B).

WHY THIS EXISTS.  TODO #237 found three wrong `status=` labels in spec/ — `oprf`,
`hske-duplex`, and the HSKE-NL rows — and identified one root cause behind all
three: they were disagreements *between documents* that no tool could see.
`spec/` said `production` where SECURITY.md said "not suitable for production",
where the proofs said "open research", and where no analysis existed at all.
`generate_spec.py --check` cannot catch that class: it verifies that the curated
tables reference live algo tags, not that what they say about them is consistent
with what SECURITY.md says.

WHAT IT CHECKS.

  1. Every protocol in spec/ is covered by a SECURITY.md row.
  2. Every SECURITY.md row maps to protocols that still exist in spec/.
  3. The row's status prose and spec/'s status enum agree.

THE MAPPING IS CURATED, AND THAT IS THE POINT.  SECURITY.md's rows are prose
written for a human deciding whether to deploy something; spec/'s statuses are a
six-value enum for machines.  Neither can be derived from the other, so the
mapping between them is a judgment recorded here — which is exactly the artifact
TODO #238 said had to be defined first.  What makes it safe is that it is
self-invalidating: checks (1) and (2) fail the moment either document gains,
loses, or renames a row, so the mapping cannot drift out from under either side
in silence.  A curated table nothing validates is what this item was filed about.

Usage:
    python3 spec/check_security_md.py          # exit 1 on any inconsistency
"""
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC_PATH = os.path.join(REPO, "spec", "herradura-protocol-spec.json")
SECURITY_MD = os.path.join(REPO, "SECURITY.md")

# ── The mapping ────────────────────────────────────────────────────────────
#
# SECURITY.md row heading (the bolded name in the first cell, verbatim) -> the
# spec/ protocol ids that row is the authority for.  A row may cover several
# ("HPKS-NL / HPKE-NL"), and a protocol may be covered by several rows (HSKE has
# one row per attack model); both are fine.  A row covering nothing in spec/ maps
# to the empty list, with the reason it is here anyway.
ROW_PROTOCOLS = {
    "HKEX-GF":                              ["hkex-gf"],
    "HPKS":                                 ["hpks"],
    "HPKE":                                 ["hpke"],
    "HPKS-NL / HPKE-NL":                    ["hpks-nl", "hpke-nl"],
    "HSKE":                                 ["hske"],          # two rows, one per attack model
    "HSKE-NL-A1":                           ["hske-nla1"],
    "HSKE-NL-A2":                           ["hske-nla2"],
    "HSKE-Duplex":                          ["hske-duplex"],
    "OPRF":                                 ["oprf"],
    "aPAKE":                                ["apake"],
    "HKEX-RNL":                             ["hkex-rnl"],
    "HKEX-RNL-128":                         [],   # withdrawn parameter set; never a shipped --algo tag
    "HPKS-Stern-F / HPKE-Stern-F":          ["hpks-stern", "hpke-stern"],
    "HPKE-Stern-KEM":                       ["hpke-stern-kem"],
    "HYBRID-RNL-STERN":                     ["hybrid-rnl-stern"],
    "HPKS-Ring":                            ["hpks-ring"],
    "HPKS-T":                               ["hpks-t"],
    "HPKS-WOTS":                            ["hpks-wots"],
    "HPKS-XMSS":                            ["hpks-xmss"],
    "HFSCX-256 / HFSCX-256-DS":             ["hfscx-256", "hfscx-256-ds"],
    "ZKP-RNL Σ-protocol":                   ["rnl-sigma"],
    "ZKBoo / ZKB++":                        ["nl-zkboo", "nl-zkbpp"],
    "HPKS-ZKP-NL":                          ["hpks-zkp-nl"],
    "HCRED":                                ["hcred"],
    "HDRBG / FPE / tweakable-wide-block":   [],   # unclassified; see unfiled_cli_surface
}

# SECURITY.md status prose -> the spec/ status values compatible with it.  Matched
# on the prose's leading phrase, so an added parenthetical ("..., stateful",
# "..., with two constraints") does not need a new entry, but a genuinely new
# verdict does.
STATUS_PROSE = [
    ("Production-track",             {"production"}),
    ("Demo-only / pedagogical",      {"demo-only", "pedagogical"}),
    ("Demo-only",                    {"demo-only"}),
    ("Not suitable for production",  {"pedagogical", "demo-only", "deprecated", "broken"}),
    ("Research",                     {"research"}),
    ("Withdrawn",                    {"deprecated", "broken"}),
    ("Unclassified",                 set()),
]


def parse_security_md(text):
    """Return {row_heading: status_prose} for the protocol table's rows."""
    rows = {}
    for line in text.splitlines():
        if not line.startswith("|") or line.startswith("|---"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2 or cells[0] == "Protocol":
            continue
        # First cell is "**Name**" possibly followed by a qualifier: "**HSKE** (key-only)".
        m = re.match(r"\*\*(.+?)\*\*", cells[0])
        if not m:
            continue
        rows.setdefault(m.group(1).strip(), cells[1])
    return rows


def allowed_statuses(prose):
    for prefix, allowed in STATUS_PROSE:
        if prose.startswith(prefix):
            return allowed
    return None


def main():
    spec = json.load(open(SPEC_PATH))
    rows = parse_security_md(open(SECURITY_MD).read())
    spec_status = {p["id"]: p["security"]["status"] for p in spec["protocols"]}
    errors = []

    # (2) every mapped row still exists, and every row is mapped.
    for heading in sorted(set(rows) - set(ROW_PROTOCOLS)):
        errors.append(
            f"SECURITY.md has a protocol row '{heading}' that spec/check_security_md.py's "
            f"ROW_PROTOCOLS does not map. Add it (map it to [] if it covers no spec/ protocol)."
        )
    for heading in sorted(set(ROW_PROTOCOLS) - set(rows)):
        errors.append(
            f"ROW_PROTOCOLS maps a SECURITY.md row '{heading}' that no longer exists in the "
            f"table. It was renamed or removed — update the mapping."
        )

    # (1) every spec/ protocol is covered.
    covered = {pid for heading in rows for pid in ROW_PROTOCOLS.get(heading, [])}
    for pid in sorted(set(spec_status) - covered):
        errors.append(
            f"spec/ classifies protocol '{pid}' ({spec_status[pid]}) but SECURITY.md has no row "
            f"for it. SECURITY.md's table is what a reader consults to decide whether to deploy "
            f"something; a protocol missing from it is one they cannot evaluate."
        )
    for heading, pids in sorted(ROW_PROTOCOLS.items()):
        for pid in pids:
            if pid not in spec_status:
                errors.append(
                    f"ROW_PROTOCOLS maps SECURITY.md row '{heading}' to protocol id '{pid}', "
                    f"which is not in spec/herradura-protocol-spec.json."
                )

    # (3) the two classifications agree.
    for heading, prose in sorted(rows.items()):
        allowed = allowed_statuses(prose)
        if allowed is None:
            errors.append(
                f"SECURITY.md row '{heading}' has status prose '{prose}', which STATUS_PROSE "
                f"does not recognise. Add it — a new verdict must be mapped deliberately, not "
                f"matched by accident."
            )
            continue
        for pid in ROW_PROTOCOLS.get(heading, []):
            if pid in spec_status and spec_status[pid] not in allowed:
                errors.append(
                    f"'{pid}': SECURITY.md row '{heading}' says '{prose}' (spec status must be one "
                    f"of {sorted(allowed) or 'none'}), but spec/ says '{spec_status[pid]}'. "
                    f"One of the two documents is wrong — this is the TODO #237 failure mode."
                )

    if errors:
        print("SECURITY.md / spec/ consistency: FAILED")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"OK: SECURITY.md and spec/ agree on all {len(spec_status)} protocols "
          f"across {len(rows)} table rows.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
