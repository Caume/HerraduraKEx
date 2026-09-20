#!/usr/bin/env python3
"""PreToolUse guard: refuse shell commands that can wait forever.

WHY THIS EXISTS.  On 2026-09-20 thirteen waiter shells were found still
spinning in this project, the oldest 3.5 days.  Twelve were the same one-line
idiom:

    until ! pgrep -f verify_kat; do sleep 20; done

`pgrep -f` matches FULL COMMAND LINES, and the waiter's own command line
contains the string `verify_kat`.  So pgrep always finds at least one match --
itself -- the negation is never true, and the loop cannot terminate.  It is not
a race or a slow job: it is a deadlock by construction, and it looks exactly
like a job that is merely taking a long time.  The thirteenth polled for an
`exit=` marker in a file that never received one, which is the same failure
from the other side: an unbounded wait on an event that is not guaranteed.

Two rules, both about TERMINATION rather than style:

  R1  A process-existence poll inside a loop must not be able to match itself.
  R2  A wait loop must be BOUNDED -- a maximum number of iterations, a deadline,
      or an outer `timeout`.  "The thing I am waiting for always happens" is an
      assumption, and an unbounded loop is what turns a wrong assumption into a
      process that outlives the session.

Exit 0 always; the verdict travels in the JSON on stdout.  A crash here must
never block real work, so everything is wrapped and fails OPEN -- this guard is
a seatbelt, not a gate, and a broken seatbelt should not stop the car.
"""
import json
import re
import sys

# A loop keyword followed eventually by `do`.  We work on the whole command
# string rather than parsing shell: the patterns below are about text that is
# present, and a false ALLOW is cheap here while a false DENY is annoying.
_LOOP = re.compile(r"\b(while|until)\b")
_SLEEP_IN_LOOP = re.compile(r"\b(while|until)\b[\s\S]*?\bdo\b[\s\S]*?\bsleep\b")

# Ways of asking "is that process still alive?" that read full command lines
# and therefore can match the asking shell itself.
_SELF_MATCHABLE = re.compile(r"\bp(?:grep|kill)\s+[^|;&\n]*-\w*f")

# Ways of saying "give up eventually".
_BOUNDED = re.compile(
    r"\bseq\s+\d"            # for i in $(seq 1 40)
    r"|\{\s*\d+\s*\.\.\s*\d+" # for i in {1..40}
    r"|\bSECONDS\b"           # while [ $SECONDS -lt 600 ]
    r"|\btimeout\s+\d"        # timeout 600 bash -c '...'
    r"|\bmax(?:_?(?:iter|tries|wait|attempts))\b"
    r"|\bdeadline\b"
)

# Self-exclusion for a process poll: drop our own pid, or match on something
# the asking shell cannot contain.
_SELF_EXCLUDED = re.compile(r"\$\$|\bgrep\s+-v\b|--older|\bpgrep\s+-x\b")

_FIX = """
Use a BOUNDED wait, and prefer a marker the job itself writes:

  # the job announces its own completion -- no process name to match
  ( ./long_job > out.log 2>&1; echo "EXIT=$?" >> out.log ) &

  # bounded poll: gives up after 40 x 15s = 10 min instead of never
  for _ in $(seq 1 40); do
      grep -q '^EXIT=' out.log && break
      sleep 15
  done
  grep '^EXIT=' out.log || echo "TIMED OUT -- job still running"

Or wrap the whole wait: timeout 600 bash -c 'until <cond>; do sleep 10; done'
If you must poll a process name, exclude yourself: pgrep -f X | grep -v $$
Better still: run it with run_in_background and let the harness notify you."""


_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def _strip_data(command):
    """Remove heredoc bodies and comment lines.

    A heredoc body is DATA -- a file being written, a commit message, a PR
    description -- not this command's control flow.  The guard learned that the
    hard way: the very commit message introducing it QUOTED the deadlocking
    idiom as the thing being fixed, and was blocked by its own rule.  Prose
    about a bad pattern is not the bad pattern.
    """
    lines = command.split("\n")
    out, i = [], 0
    while i < len(lines):
        line = lines[i]
        m = _HEREDOC.search(line)
        out.append(line)
        i += 1
        if m:
            tag = m.group(2)
            while i < len(lines) and lines[i].strip() != tag:
                i += 1
            if i < len(lines):
                out.append(lines[i])   # keep the terminator, drop the body
                i += 1
    return "\n".join(l for l in out if not l.lstrip().startswith("#"))


def verdict(command):
    """Return a deny reason, or None to allow."""
    command = _strip_data(command)
    if not _LOOP.search(command):
        return None

    problems = []
    if _SELF_MATCHABLE.search(command) and not _SELF_EXCLUDED.search(command):
        problems.append(
            "R1: this loop polls with `pgrep -f`/`pkill -f`, which matches FULL "
            "COMMAND LINES — including this shell's own, since the pattern is "
            "written right here in it. The poll will always find itself, so the "
            "loop can never terminate. Thirteen shells were leaked this exact "
            "way in this project, the oldest running 3.5 days.")

    if _SLEEP_IN_LOOP.search(command) and not _BOUNDED.search(command):
        problems.append(
            "R2: this wait loop has no bound — no iteration cap, no deadline, no "
            "outer `timeout`. If the thing it waits for never arrives (a job that "
            "died before writing its marker, a condition that is subtly always "
            "false), it runs until the machine reboots.")

    if not problems:
        return None
    return "Blocked: a shell loop that may never terminate.\n\n" \
        + "\n\n".join(problems) + "\n" + _FIX


def main():
    try:
        data = json.load(sys.stdin)
        command = (data.get("tool_input") or {}).get("command") or ""
        reason = verdict(command)
    except Exception:
        return  # fail OPEN: never block real work because the guard broke
    if reason:
        json.dump({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }}, sys.stdout)


if __name__ == "__main__":
    main()
    sys.exit(0)
