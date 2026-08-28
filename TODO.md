# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

New items go here with `Status: **OPEN**`; see CLAUDE.md.

---

### #242: `fpe` and `twk` share a subkey derivation and compute the same function

Found by TODO #241's analysis of the unclassified CLI surface, and deliberately left
unfixed there: #241 is an analysis item, and this fix changes what two shipped
subcommands produce.

Both derive their 256-bit subkey with the same unseparated hash call:

| | derivation |
|---|---|
| `fpe` | `B = HFSCX-256(key ‖ ctx)` |
| `twk` | `B = HFSCX-256(key ‖ sector_be64 ‖ bidx_be32)` |

Neither carries a domain-separation tag, so a 12-byte `ctx` equal to
`sector_be64 ‖ bidx_be32` makes the two subcommands the identical function.  Verified
byte-identical across the C, Go and Python CLIs, in both directions — `twk --decrypt`
recovers a plaintext that `fpe --encrypt` produced:

```
$CLI fpe --context '0123456789:;'                      --encrypt --in pt --out a
$CLI twk --sector 3472611983179986487 --bidx 943274555 --encrypt --in pt --out b
cmp a b        # identical
```

Two separately-advertised primitives reachable under one key are therefore not
independent, which is the only reason to ship both.  See SecurityProofs-7.md §11.24.1
and `SecurityProofsCode/rand_fpe_twk_analysis.py` §2.

**Work.**  Give each primitive its own domain-separation tag via `hfscx_256_ds` (TODO
#93), whose namespace already has `0x01`–`0x03` and `0x10`–`0x12` allocated, and
length-prefix the key so the `key ‖ tweak` boundary stops being ambiguous — `drbg_seed`
in the same file and TODO #235's KEM work both already do this.  Land it identically in
C, Go and Python (Java ships neither subcommand).  Consider also calling
`nl_v2_key_is_valid` on the derived subkey for defence in depth; the exposure is
negligible because `B` is a hash output, but the check exists and is used elsewhere.

**This is a MAJOR-class change and must be treated as one.**  It changes what an
existing `--algo`-equivalent CLI surface produces: every `fpe` and `twk` ciphertext
written by any prior build becomes undecryptable by the fixed build, and the failure is
silent — both subcommands are unauthenticated permutations, so a wrong subkey yields
plaintext-shaped garbage rather than an error.  Per CLAUDE.md that needs a `MIGRATING.md`
entry alongside the version bump, and this item is the required explicit call-out.

**Test coverage, which must land with the fix.**  `fpe` and `twk` have no `CliTest`
script at all — no CLI-level test and no cross-language interop test, in a repo whose CI
runs a four-language matrix over every other protocol family.  That C, Go and Python
currently agree byte-for-byte was established by hand for #241 and is guarded by nothing.
The suite-level `test_fpe_correctness` / `test_twk_correctness` do not close this: they
re-implement the construction locally (`_fpe_derive_b`, `fpe_encrypt_test`,
`twk_encrypt_test`) and round-trip against the copy, so the shipped `fpe_encrypt` and
`twk_encrypt` are never called by any test, and the round-trip property they assert is a
tautology for any bijection — it would pass even with the subkey derivation deleted.  Add
a `CliTest` script exercising the shipped subcommands across all three CLIs, and make the
suite tests call the real functions.  A regression test that the two primitives no longer
collide is the specific thing this item must not ship without.

**Not in scope.**  The `fpe` naming defect (it is not format-preserving encryption in
the SP 800-38G sense — no radix, no domain, 32 bytes in and out).  That is a separate
question — rename, re-scope, or implement a real FF1/FF3-1 domain — and it should not be
bundled with a wire-format fix.  SECURITY.md's `fpe` row records it meanwhile.

**Worth deciding first.**  Whether `fpe` should keep existing at all once it is
domain-separated from `twk`: with the naming defect on one side and `twk` covering the
tweaked-permutation use case on the other, a deprecation may be cheaper than a fix.
#241 put removal out of its own scope but did not rule it out here.

Status: **OPEN**
