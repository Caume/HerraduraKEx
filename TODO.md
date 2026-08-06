# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

### 178. Promote the suite to v2.0.0 (Release, Medium)

A survey of the repo (2026-08-06) found `TODO.md` empty, all six main teaching/reference
docs recently overhauled (TODO #172–177), and no new cryptographic work blocking a
release — but three legitimate breaking changes from the 1.x history (HKEX→HKEX-GF at
v1.4.0, HFSCX-256→HFSCX-256-DM at v1.9.0, the Stern H-matrix fix at v1.9.35) had never
been consolidated into one migration story. 2.0.0 is proposed to mark the CLI/PEM
surface as a stable baseline going forward, not to introduce a new break of its own.

**Work items:**

1. ~~Write `MIGRATING.md` consolidating the three historical breaking changes with
   what's incompatible and how to regenerate affected artifacts.~~ **Done.**
2. ~~Add a "Known Limitations" section to `README.md`~~ **Done** — HPKS-NL/HPKE-NL not
   PQC (TODO #5), HPKS-Stern-F/HPKE-Stern-F demo-scale parameters, the two
   ACKNOWLEDGED-by-design test FAILs (#85, #86), Arduino CI's best-effort status, and
   the QC-MDPC/Ligero research prototypes.
3. Re-verify `CliTest/test_c_interop.sh` and `CliTest/test_go_interop.sh` pass
   byte-for-byte across all three CLIs before tagging, since 2.0.0 is meant to freeze
   this surface as the stable baseline.
4. Add a short addendum to CLAUDE.md's TODO policy section on when MINOR/MAJOR version
   bumps apply post-2.0.0 (currently only PATCH-per-TODO is documented).
5. Tag `v2.0.0`, write GitHub release notes pointing to `MIGRATING.md`, and do a fresh
   `docker build && docker run` check to confirm the release artifact builds clean.

Status: **OPEN**
