#!/usr/bin/env python3
"""Negative and positive controls for guard-polling-loops.py.

Run from the repo root: python3 .claude/hooks/test_guard_polling_loops.py

A guard that blocks real work is worse than no guard, so the ALLOW cases
outnumber the DENY ones and are taken from commands actually used in this
project.  The DENY cases are the two shapes that leaked thirteen shells here.
Exits non-zero if any decision changes.
"""
import json, subprocess, sys
H = ".claude/hooks/guard-polling-loops.py"
def ask(cmd):
    p = subprocess.run([sys.executable, H], input=json.dumps(
        {"tool_name":"Bash","tool_input":{"command":cmd}}),
        capture_output=True, text=True)
    assert p.returncode == 0, f"hook exited {p.returncode}: {p.stderr}"
    if not p.stdout.strip(): return "ALLOW", ""
    d = json.loads(p.stdout)["hookSpecificOutput"]
    return d["permissionDecision"].upper(), d["permissionDecisionReason"]

CASES = [
 # (expected, label, command)
 ("DENY", "the exact idiom that leaked 12 shells",
  'until ! pgrep -f "verify_kat" >/dev/null; do sleep 20; done; cat out.txt'),
 ("DENY", "the 13th: unbounded marker wait",
  "until grep -q 'EXIT=' /tmp/log 2>/dev/null; do sleep 15; done; tail -3 /tmp/log"),
 ("DENY", "while-loop variant on pgrep",
  'while pgrep -f kkwcost.py > /dev/null; do sleep 10; done; echo done'),
 ("DENY", "pkill -f poll",
  'until pkill -f zkboo_probe2; do sleep 5; done'),
 ("DENY", "unbounded wait on a file appearing",
  'while [ ! -f /tmp/done.flag ]; do sleep 30; done; cat /tmp/done.flag'),

 ("ALLOW", "BOUNDED poll with seq (the fix I used today)",
  'for i in $(seq 1 40); do grep -q "^EXIT=" /tmp/csuite.log && break; sleep 15; done; tail -2 /tmp/csuite.log'),
 ("ALLOW", "bounded with brace range",
  'for i in {1..30}; do [ -f /tmp/f ] && break; sleep 10; done'),
 ("ALLOW", "outer timeout wrapper",
  "timeout 600 bash -c 'until grep -q X /tmp/f; do sleep 5; done'"),
 ("ALLOW", "SECONDS deadline",
  'while [ $SECONDS -lt 600 ]; do grep -q X /tmp/f && break; sleep 5; done'),
 # Self-exclusion fixes R1 but NOT R2: a process that simply never exits still
 # hangs the loop forever.  Both rules must pass, which is the point.
 ("DENY", "pgrep self-excluded but still unbounded (R2 only)",
  'until ! pgrep -f verify_kat | grep -v $$ > /dev/null; do sleep 20; done'),
 ("ALLOW", "self-excluded AND bounded",
  'for _ in $(seq 1 60); do pgrep -f verify_kat | grep -v $$ >/dev/null || break; sleep 10; done'),

 ("ALLOW", "plain pgrep, no loop", 'pgrep -af "Herradura_tests_c"'),
 ("ALLOW", "ordinary checker run", 'python3 spec/check_language_parity.py'),
 ("ALLOW", "loop with no sleep", 'for f in *.c; do gcc -O2 -c "$f"; done'),
 ("ALLOW", "while-read over a file", 'while read -r l; do echo "$l"; done < /tmp/w.txt'),
 ("ALLOW", "git + build", './build_c.sh && git status --short'),
 ("ALLOW", "the real kill command from earlier",
  'for p in $PIDS; do kill -TERM "$p" 2>/dev/null; done'),
 # Heredoc bodies are DATA, not control flow.  The commit message that
 # introduced this guard quoted the deadlocking idiom as the thing being
 # fixed, and the first version of the guard blocked it.
 ("ALLOW", "commit message that QUOTES the bad idiom in a heredoc",
  "git commit -F - <<'EOF'\nFix the leak\n\n    until ! pgrep -f verify_kat; do sleep 20; done\n\nis a deadlock.\nEOF"),
 ("ALLOW", "writing a doc that describes an unbounded loop",
  'cat > notes.md <<"MD"\nAvoid: while [ ! -f f ]; do sleep 30; done\nMD'),
 ("ALLOW", "a comment mentioning the pattern",
  '# until ! pgrep -f x; do sleep 5; done  <- never do this\necho ok'),
 ("DENY", "real loop AFTER a heredoc still caught",
  "cat > f <<'EOF'\nhello\nEOF\nuntil ! pgrep -f verify_kat; do sleep 20; done"),
 ("ALLOW", "background job with marker (recommended idiom)",
  '( ./CryptosuiteTests/Herradura_tests_c -r 20 > /tmp/o.log 2>&1; echo "EXIT=$?" >> /tmp/o.log ) &'),
]
ok = 0
for want, label, cmd in CASES:
    got, reason = ask(cmd)
    good = got == want
    ok += good
    print(f"[{'ok ' if good else 'BAD'}] {got:<5} (want {want:<5}) {label}")
    if not good: print(f"        cmd: {cmd}\n        reason: {reason[:200]}")
print(f"\n{ok}/{len(CASES)} hook decisions correct")
sys.exit(0 if ok == len(CASES) else 1)
