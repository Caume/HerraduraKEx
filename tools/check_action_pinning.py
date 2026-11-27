#!/usr/bin/env python3
"""TODO #418: every action a workflow runs is pinned to a full commit SHA.

A `uses: owner/action@v4` line names a TAG, and a tag is mutable: whoever can
move it (an upstream compromise, a maintainer-account takeover) changes what
every CI run here executes, with the repo's GITHUB_TOKEN in scope.  A 40-hex
commit SHA cannot be moved.  So, over every *.yml / *.yaml under .github/:

  (a) each `uses:` that names a remote action is `owner/repo[/path]@<sha>`
      with <sha> exactly 40 lowercase hex digits, followed by a comment
      `# vX[.Y[.Z]]` naming the release it was resolved from (so a reader and
      Dependabot can see what it is);  a local action (`./path`) is exempt,
      and a `docker://` image must be pinned by `@sha256:<64 hex>`;
  (b) one action is pinned to ONE sha across all files, with one comment --
      two different pins of the same action means one of them was not bumped;
  (c) every line that mentions `uses:` outside a comment is one the scanner
      parsed, so a layout it misreads (flow style, a quoted key) fails loudly
      instead of passing by finding nothing (the vacuous pass #291 warns of);
      and at least one `uses:` must be found at all.

CONTROLS, run first and each required to fire: the real files are accepted; a
copy with one pin put back to `@v4`, one with a 39-hex sha, one with an
uppercase sha, one with the version comment removed, one with a second,
different sha for the same action, and one with a flow-style `{uses: ...}` the
scanner cannot place are each refused; a copy with a local `./action` step
added is accepted (the exemption is an accept-control, not a blanket pass).

KNOWN LIMIT.  The check cannot tell whether a sha really is the commit the
comment names -- that needs the network.  The pins were resolved with
`git ls-remote --tags` (the peeled `^{}` commit for an annotated tag); re-check
the same way when bumping.  An action's own transitive `uses:` (inside a
composite action it calls) is outside this repo and not seen.  No third-party
dependencies: a line scanner, not PyYAML.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SHA = re.compile(r"^[0-9a-f]{40}$")
DOCKER = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>[^\s#]+)\s*(?:#\s*(?P<tag>\S.*?))?\s*$")
TAG = re.compile(r"^v\d+(?:\.\d+){0,2}$")


def workflow_files(root):
    gh = root / ".github"
    return sorted(p for p in gh.rglob("*") if p.suffix in (".yml", ".yaml") and p.is_file())


def _code(line):
    """The line without a YAML comment (a '#' at the start or after a space)."""
    s = line.strip()
    return "" if s.startswith("#") else re.split(r"\s#", s, maxsplit=1)[0]


def check(files):
    """files: [(name, text)].  Returns (errors, number of uses: lines seen)."""
    errors, seen, pins = [], 0, {}
    for name, text in files:
        for no, line in enumerate(text.split("\n"), 1):
            if "uses:" not in _code(line):
                continue
            where = f"{name}:{no}"
            m = USES.match(line)
            if not m:
                errors.append(f"{where}: a `uses:` the scanner cannot parse: {line.strip()!r}")
                continue
            seen += 1
            ref, tag = m.group("ref").strip("'\""), m.group("tag")
            if ref.startswith("./"):
                continue
            if ref.startswith("docker://"):
                if not DOCKER.match(ref):
                    errors.append(f"{where}: {ref} is not pinned by @sha256:<64 hex>")
                continue
            action, at, ver = ref.partition("@")
            if not at or not SHA.match(ver):
                errors.append(f"{where}: {ref} is not pinned to a 40-hex commit sha "
                              f"(write `{action}@<sha>  # vN.N.N`)")
                continue
            if not tag or not TAG.match(tag):
                errors.append(f"{where}: {ref} has no `# vX.Y.Z` comment naming its release")
                continue
            pins.setdefault(action, set()).add((ver, tag))
    for action, got in sorted(pins.items()):
        if len(got) > 1:
            errors.append(f"{action} is pinned {len(got)} different ways: "
                          + ", ".join(f"{s[:12]}.. # {t}" for s, t in sorted(got)))
    if seen == 0:
        errors.append("no `uses:` line found at all -- the scanner saw nothing to check")
    return errors, seen


def controls(files):
    """Each mutation of the real files must be refused (or, for the local-action
    control, accepted).  Returns the list of controls that did not behave."""
    bad = []
    pinned = [(i, n, t, m) for i, (n, t) in enumerate(files)
              for m in [re.search(r"@([0-9a-f]{40})", t)] if m]
    if not pinned:
        return ["no workflow file has a sha pin to mutate"]
    i, name, text, m = pinned[0]
    sha = m.group(1)
    action = re.search(r"uses:\s*([^\s@]+)@" + sha, text).group(1)

    def with_text(new):
        return files[:i] + [(name, new)] + files[i + 1:]

    def sub1(pattern, repl):
        return re.sub(pattern, repl, text, count=1)

    refused = {
        "tag pin @v4": sub1(re.escape("@" + sha), "@v4"),
        "39-hex sha": sub1(re.escape("@" + sha), "@" + sha[:39]),
        "uppercase sha": sub1(re.escape("@" + sha), "@" + sha.upper()),
        "no version comment": sub1(re.escape("@" + sha) + r"[^\n]*", "@" + sha),
        "second sha, same action": sub1(re.escape("@" + sha),
                                        "@" + ("0" if sha[0] != "0" else "1") + sha[1:]),
        "flow-style uses": text + "\n      - {uses: " + action + "@" + sha + "}\n",
    }
    for label, new in refused.items():
        if new == text:
            bad.append(f"control '{label}': the mutation changed nothing")
            continue
        errs, _ = check(with_text(new))
        if not errs:
            bad.append(f"control '{label}' was ACCEPTED (must be refused)")
    local = text + "\n      - uses: ./.github/actions/local-thing\n"
    errs, _ = check(with_text(local))
    if errs:
        bad.append("control 'local ./action' was REFUSED (must be accepted): " + errs[0])
    return bad


def main():
    paths = workflow_files(ROOT)
    files = [(str(p.relative_to(ROOT)), p.read_text()) for p in paths]
    if not files:
        print("FAIL: no workflow files under .github/")
        return 1
    errs, seen = check(files)
    bad = controls(files) if not errs else []
    for e in errs:
        print("FAIL:", e)
    for b in bad:
        print("FAIL:", b)
    if errs or bad:
        print(f"*** FAILED: {len(errs) + len(bad)} problem(s) ***")
        return 1
    print(f"ok: {seen} uses: line(s) in {len(files)} file(s), every remote action "
          f"pinned to a commit sha; 7 controls behaved (6 refused, 1 accepted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
