# Coverage counts

The numbers the checkers print about their own coverage, in one place.  Each row
is held to the tool that emits it by `spec/check_docs_consistency.py` check E
(TODO #287), so a stale figure fails CI rather than going unnoticed.  The table is
exhaustive in both directions: a row with no `DOC_COUNTS` entry fails, and so does
a `DOC_COUNTS` entry with no row.

These rows used to be sentences scattered through `CLAUDE.md`; they moved here so
that file can stay a short working guide.  Edit a number only to match what the
named tool prints.

| count | value | emitted by |
|---|---|---|
| suite-internal primitive manifest | 202 | `spec/check_language_parity.py` (`PRIMITIVES`, four cells each) |
| PARAMETERS table | 85 | `spec/check_language_parity.py` (TODO #278, four cells each) |
| findings-gating analysis scripts | 86 | `SecurityProofsCode/run_findings_gates.py --list` (TODO #289) |
| fresh-sampling findings gates | 29 | `SecurityProofsCode/run_findings_gates.py --list` (`SAMPLED_GATES`, TODO #300) |
| nominal job false-failure rate | 6.4e-05 | `SecurityProofsCode/run_findings_gates.py --list` (per `analysis-findings` run, TODO #304) |
| numbered-test flake budget | 1.0e-05 | `spec/check_language_parity.py` (summed over sampled numbered tests, TODO #316/#319) |
| rates evaluated from source | 8 | `spec/check_language_parity.py` (`_SAMPLED_TEST_RATES`, TODO #319) |
| rate mechanisms measured | 8 | `spec/check_language_parity.py` (`_RATE_MECHANISMS`, TODO #320) |
| argued rows with measured evidence | 2 | `spec/check_language_parity.py` (`_ARGUED_MEASUREMENTS`, TODO #321) |
| rejection cells with a stated basis | 32 | `spec/check_language_parity.py` (`_REJECTION_BASES`, TODO #322) |
| gated harnesses the sampled-test axis reads | 3 | `spec/check_language_parity.py` (`_REDUCED_HARNESSES`, beyond the four main ones, TODO #323) |
| pinned leaf samplers | 4 | `spec/check_language_parity.py` (`KAT/sampler_replay.json`, TODO #296) |
| pinned whole operations | 10 | `spec/check_language_parity.py` (`KAT/operation_replay.json`, TODO #297) |
| replay pins still owed | 0 | `spec/check_language_parity.py` (`REPLAY_COVERAGE`, TODO #305) |
| CLI raw-entropy sites | 56 | `spec/check_language_parity.py` (`CLI_DRAW_COVERAGE`, TODO #306) |
