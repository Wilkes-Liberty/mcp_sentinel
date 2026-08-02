#!/usr/bin/env python3
"""Rewrite PR commits to drop AI-attribution trailers from their messages.

Wilkes & Liberty work reads as authored by the human operator. Local commit
hooks cannot see server-side commits (GitHub "Commit suggestion", Copilot
Autofix, web UI). The companion check-attribution.py *fails* a dirty PR; this
script *cleans* the PR branch when it can, so the operator does not have to
hand-rebase every Copilot trailer before merge.

Scope (deliberately narrow):
  * Only rewrites **commit messages** in base..head (non-merge commits).
  * Only removes attribution *shapes* — credit trailers naming an AI author,
    "Generated with <AI>" footers, and the robot-emoji marker line.
  * Preserves human Co-authored-by trailers, trees, author identity, and
    author/committer dates.
  * Does **not** edit PR title/body (the check still gates those).
  * Does **not** rewrite mid-subject prose like "AI-assisted refactor" — those
    still fail the check for a human reword (auto-rewriting subjects is too
    lossy).

Usage:
  strip-attribution.py --base <sha> --head <sha> [--push] [--dry-run]
                       [--branch <name>] [--force-with-lease-ref <spec>]

Exits:
  0  clean already, or successfully rewrote (and pushed if --push)
  1  rewrite needed but failed, or residual dirty messages remain
  2  usage / environment error

GitHub Actions: writes `stripped` and `count` to $GITHUB_OUTPUT when set.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from typing import List, Optional, Tuple

# --- BEGIN SHARED PATTERNS (keep identical to check-attribution.py) ---

AI_AUTHOR = (
    r"claude|anthropic|copilot|codex|cursor|devin|aider|windsurf|"
    r"chatgpt|openai|gemini|llama|"
    r"powered\s+by\s+ai|\bai\s+(?:assistant|agent|bot)\b"
)

CREDIT_TRAILER = r"Co-?Authored-?By|Co-?Committed-?By|Assisted-?By|Generated-?By"

# Line-oriented shapes safe to auto-remove. The broader "AI-generated" mid-prose
# pattern lives only in check-attribution.py so subjects still need a human.
STRIP_LINE_PATTERNS = [
    re.compile(rf"^(?:{CREDIT_TRAILER})\s*:\s*.*(?:{AI_AUTHOR})", re.I),
    re.compile(rf"^(?i:(?:{CREDIT_TRAILER})\s*:)\s*.*\bAI\b"),
    re.compile(
        rf"^\s*(?:\U0001F916\s*)?(?:Generated|Created|Written|Authored|Produced)\s+(?:with|by)\s+"
        rf".*(?:{AI_AUTHOR})",
        re.I,
    ),
    re.compile(r"^\s*\U0001F916\s*$"),  # a line that is ONLY the robot emoji
]

# --- END SHARED PATTERNS ---


def git(args: List[str], *, check: bool = True, text: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        capture_output=True,
        text=text,
        check=check,
    )


def short(rev: str) -> str:
    return rev[:12] if re.fullmatch(r"[0-9a-f]{40}", rev) else rev


def should_strip_line(line: str) -> bool:
    # Ignore pure whitespace; keep blank lines for structure until we collapse.
    if not line.strip():
        return False
    return any(p.search(line) for p in STRIP_LINE_PATTERNS)


def clean_message(message: str) -> Tuple[str, List[str]]:
    """Return (cleaned_message, removed_lines).

    Preserves the subject line even if it would match a strip pattern, so we
    never produce a subject-less commit. Residual subject-level attribution is
    the check's job.

    Returns the message unchanged when nothing matched, so a clean commit is
    never rewritten.

    Known limitation, stated because the patterns cannot express the
    difference: matching is on the author *name* as well as the address, so a
    human co-author who happens to be called Claude, Devin or Gemini is
    stripped along with the machines. Erring that way is deliberate -- §1 is
    absolute and a missed trailer is unrecoverable once tagged -- but it is a
    real false positive. Every removed line is reported, so a wrongly dropped
    human co-author is visible in the run and can be restored by hand.
    """
    # Normalize to lines without a guaranteed trailing newline for processing.
    raw = message.replace("\r\n", "\n").replace("\r", "\n")
    if raw.endswith("\n"):
        raw = raw[:-1]
    lines = raw.split("\n")
    if not lines:
        return "\n", []

    removed: List[str] = []
    out: List[str] = [lines[0]]  # subject always kept
    for line in lines[1:]:
        if should_strip_line(line):
            removed.append(line)
            continue
        out.append(line)

    # Whitespace normalization is repair for the gap a removed trailer leaves,
    # so it only runs when something was removed. Doing it unconditionally
    # rewrites and force-pushes commits that were already clean, purely for
    # formatting -- which is outside this tool's stated scope, and would report
    # those commits as having carried attribution when they did not.
    if not removed:
        return message, []

    # Drop trailing blank lines in the body (keep subject even if alone).
    while len(out) > 1 and out[-1].strip() == "":
        out.pop()
    # Collapse runs of blank lines left by trailer removal (body only).
    collapsed: List[str] = [out[0]]
    blank_run = False
    for line in out[1:]:
        if line.strip() == "":
            if blank_run:
                continue
            blank_run = True
            collapsed.append("")
        else:
            blank_run = False
            collapsed.append(line)

    cleaned = "\n".join(collapsed) + "\n"
    return cleaned, removed


def commits_oldest_first(base: str, head: str) -> List[Tuple[str, str]]:
    """(sha, full message) for each non-merge commit in base..head, oldest first."""
    sep = "\x1e"
    out = git(
        ["log", "--reverse", "--topo-order", "--no-merges", f"--format=%H{sep}%B%x00", f"{base}..{head}"]
    ).stdout
    commits: List[Tuple[str, str]] = []
    for record in out.split("\x00"):
        record = record.strip("\n")
        if not record:
            continue
        parts = record.split(sep, 1)
        if len(parts) == 2:
            commits.append((parts[0], parts[1]))
    return commits


def commit_meta(sha: str) -> dict:
    """Author/committer identity and dates for a commit (raw %aN etc.)."""
    fmt = "%aN%x1f%aE%x1f%aD%x1f%cN%x1f%cE%x1f%cD%x1f%T"
    line = git(["log", "-1", f"--format={fmt}", sha]).stdout.rstrip("\n")
    parts = line.split("\x1f")
    if len(parts) != 7:
        raise RuntimeError(f"unexpected meta for {sha}: {line!r}")
    return {
        "author_name": parts[0],
        "author_email": parts[1],
        "author_date": parts[2],
        "committer_name": parts[3],
        "committer_email": parts[4],
        "committer_date": parts[5],
        "tree": parts[6],
    }


def first_parent(sha: str) -> Optional[str]:
    out = git(["rev-list", "--parents", "-n", "1", sha]).stdout.strip().split()
    if len(out) < 2:
        return None
    return out[1]


def write_commit(tree: str, parent: Optional[str], message: str, meta: dict) -> str:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": meta["author_name"],
            "GIT_AUTHOR_EMAIL": meta["author_email"],
            "GIT_AUTHOR_DATE": meta["author_date"],
            "GIT_COMMITTER_NAME": meta["committer_name"],
            "GIT_COMMITTER_EMAIL": meta["committer_email"],
            "GIT_COMMITTER_DATE": meta["committer_date"],
        }
    )
    args = ["commit-tree", tree]
    if parent:
        args.extend(["-p", parent])
    proc = subprocess.run(
        ["git", *args],
        input=message,
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    return proc.stdout.strip()


def rewrite_range(base: str, head: str) -> Tuple[str, int, List[str]]:
    """Rewrite dirty messages in base..head. Returns (new_head, n_stripped, notes)."""
    commits = commits_oldest_first(base, head)
    if not commits:
        return head, 0, []

    # Map old sha -> new sha for parent retargeting along the linear chain.
    # For non-merge commits the first parent is the previous rewritten tip when
    # the commit sits on the PR branch lineage.
    mapping: dict = {}
    notes: List[str] = []
    stripped = 0
    new_tip = head

    # Walk oldest → newest so parents exist before children.
    for sha, message in commits:
        cleaned, removed = clean_message(message)
        meta = commit_meta(sha)
        old_parent = first_parent(sha)
        new_parent = mapping.get(old_parent, old_parent) if old_parent else None

        if not removed and cleaned == (
            message if message.endswith("\n") else message + "\n"
        ):
            # Message unchanged. Still may need a new commit if parent moved.
            if old_parent and new_parent != old_parent:
                new_sha = write_commit(meta["tree"], new_parent, cleaned, meta)
                mapping[sha] = new_sha
                new_tip = new_sha
            else:
                mapping[sha] = sha
                new_tip = sha
            continue

        # Normalize comparison: treat missing final newline as equivalent.
        original_norm = message if message.endswith("\n") else message + "\n"
        if cleaned == original_norm and not removed:
            mapping[sha] = sha
            new_tip = sha
            continue

        new_sha = write_commit(meta["tree"], new_parent, cleaned, meta)
        mapping[sha] = new_sha
        new_tip = new_sha
        stripped += 1
        notes.append(
            f"{short(sha)} → {short(new_sha)}: removed {len(removed)} line(s)"
        )
        for line in removed:
            notes.append(f"    - {line.rstrip()}")

    return new_tip, stripped, notes


def set_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def resolve_branch(explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    # Detached HEAD is common in Actions; prefer GITHUB_HEAD_REF.
    env_branch = os.environ.get("GITHUB_HEAD_REF") or os.environ.get("BRANCH")
    if env_branch:
        return env_branch
    ref = git(["rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    if ref and ref != "HEAD":
        return ref
    raise RuntimeError(
        "cannot determine branch name; pass --branch or set GITHUB_HEAD_REF"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="PR base sha")
    parser.add_argument("--head", required=True, help="PR head sha or ref")
    parser.add_argument(
        "--push",
        action="store_true",
        help="force-with-lease push the rewritten tip to origin",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be stripped without rewriting",
    )
    parser.add_argument("--branch", help="branch name to update / push")
    parser.add_argument(
        "--force-with-lease-ref",
        help="lease spec BRANCH:EXPECTED (default: <branch>:<resolved-head>)",
    )
    args = parser.parse_args()

    try:
        head_sha = git(["rev-parse", args.head]).stdout.strip()
        base_sha = git(["rev-parse", args.base]).stdout.strip()
    except subprocess.CalledProcessError as exc:
        print(
            "::error::could not resolve base/head. Does the checkout use fetch-depth: 0?",
            file=sys.stderr,
        )
        print(exc.stderr or "", file=sys.stderr)
        return 2

    merges = git(["rev-list", "--merges", f"{base_sha}..{head_sha}"]).stdout.strip()
    if merges:
        print(
            f"::warning::strip-attribution: merge commits detected in {short(base_sha)}..{short(head_sha)}; "
            "auto-rewrite only supports linear history. Please rebase to a linear branch and re-run."
        )
        set_output("stripped", "false")
        set_output("count", "0")
        return 0

    commits = commits_oldest_first(base_sha, head_sha)
    dirty = []
    for sha, message in commits:
        cleaned, removed = clean_message(message)
        original_norm = message if message.endswith("\n") else message + "\n"
        if removed or cleaned != original_norm:
            dirty.append((sha, removed))

    if not dirty:
        print(f"strip-attribution: clean ({short(base_sha)}..{short(head_sha)}, "
              f"{len(commits)} commit(s))")
        set_output("stripped", "false")
        set_output("count", "0")
        return 0

    print(
        f"strip-attribution: {len(dirty)} commit(s) carry removable AI attribution "
        f"in {short(base_sha)}..{short(head_sha)}"
    )
    for sha, removed in dirty:
        print(f"  {short(sha)}:")
        for line in removed:
            print(f"    - {line.rstrip()}")

    if args.dry_run:
        set_output("stripped", "false")
        set_output("count", str(len(dirty)))
        print("strip-attribution: dry-run only; no rewrite")
        return 0

    try:
        new_tip, count, notes = rewrite_range(base_sha, head_sha)
    except (subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"::error::rewrite failed: {exc}", file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stderr or "", file=sys.stderr)
        set_output("stripped", "false")
        set_output("count", "0")
        return 1

    for note in notes:
        print(note)

    if count == 0:
        # Dirty lines reported but rewrite found nothing (shouldn't happen).
        print("::warning::reported dirty commits but rewrite made no changes")
        set_output("stripped", "false")
        set_output("count", "0")
        return 1

    if new_tip == head_sha:
        print("::error::strip count > 0 but tip unchanged", file=sys.stderr)
        return 1

    # Point HEAD / branch at the rewritten tip locally.
    try:
        branch = resolve_branch(args.branch)
    except RuntimeError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2

    # Update the local branch ref. Works for attached and for explicit branch.
    git(["update-ref", f"refs/heads/{branch}", new_tip])
    # Move HEAD if we are on a detached checkout of the old tip.
    try:
        git(["checkout", "-B", branch, new_tip])
    except subprocess.CalledProcessError as exc:
        print(f"::warning::checkout -B failed (ref updated anyway): {exc.stderr}")

    if args.push:
        lease = args.force_with_lease_ref or f"{branch}:{head_sha}"
        # Accept either "branch:sha" or full "refs/heads/branch:sha".
        if ":" in lease and not lease.startswith("refs/"):
            b, expected = lease.split(":", 1)
            lease_arg = f"refs/heads/{b}:{expected}"
        elif lease.startswith("refs/"):
            lease_arg = lease
        else:
            lease_arg = f"refs/heads/{branch}:{head_sha}"

        push = subprocess.run(
            [
                "git",
                "push",
                "--force-with-lease=" + lease_arg,
                "origin",
                f"refs/heads/{branch}:{branch}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if push.returncode != 0:
            print("::error::force-with-lease push failed", file=sys.stderr)
            print(push.stderr or push.stdout or "", file=sys.stderr)
            set_output("stripped", "false")
            set_output("count", "0")
            return 1
        print(f"strip-attribution: pushed {branch} → {short(new_tip)} "
              f"(lease {lease_arg})")

    set_output("stripped", "true")
    set_output("count", str(count))
    print(f"strip-attribution: rewrote {count} commit(s); tip {short(new_tip)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
