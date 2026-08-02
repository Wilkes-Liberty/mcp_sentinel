#!/usr/bin/env python3
"""Fail a pull request whose commits, identities, or prose carry AI-attribution credit.

Wilkes & Liberty work reads as authored by the human operator. This is not about
hiding that AI tooling is used -- naming a tool, or shipping a CLAUDE.md, is
fine. The rule is about authorship and contribution CREDIT.

Three surfaces are scanned, because credit lands on all three: commit MESSAGES,
the commit AUTHOR and COMMITTER identities, and the PR title and body. The
identity scan was added after a pull request merged with `copilot-swe-agent[bot]`
in its author field and passed this check cleanly -- the trailers had been
stripped, and nothing looked at who the commit said wrote it.

A local commit hook cannot cover this on its own. GitHub composes "Commit
suggestion", "Apply suggestion" and Copilot Autofix commits **server-side**, so
no local `git commit` runs and no local hook fires. Once such a commit is merged
and tagged the trailer cannot be removed, because a tag pins history
permanently. Before merge is the only cheap window, which is where this runs.

This script is a drop-in: copy it and `attribution.yml` into a repo's
`.github/`. It is deliberately standalone and stdlib-only, so it runs on any
runner with no install step and a repo that vendors it takes on no dependency.

Usage:
  check-attribution.py --base <sha> --head <sha> [--title-file F] [--body-file F]

Exits 0 when clean, 1 when an attribution is found, 2 on a usage error.

PATTERNS is kept identical to the local commit guard's list. Edit one, edit
both, or the two controls start disagreeing about what is forbidden.
"""

import argparse
import re
import subprocess
import sys

# --- BEGIN SHARED PATTERNS (keep identical to the local commit guard) ---

# Names that identify an AI author. These only ever match *inside* an
# attribution construct below, never on their own, so mentioning a vendor in a
# subject line is fine.
AI_AUTHOR = (
    r"claude|anthropic|copilot|codex|cursor|devin|aider|windsurf|"
    r"chatgpt|openai|gemini|llama|"
    r"powered\s+by\s+ai|\bai\s+(?:assistant|agent|bot)\b"
)

# Trailer keys that assign authorship or contribution credit.
CREDIT_TRAILER = r"Co-?Authored-?By|Co-?Committed-?By|Assisted-?By|Generated-?By"

# Attribution shapes, not the mere mention of a name.
PATTERNS = [
    (
        re.compile(rf"(?:{CREDIT_TRAILER})\s*:\s*[^\n]*(?:{AI_AUTHOR})", re.I),
        "a co-author trailer crediting an AI author",
    ),
    (
        # Only \bAI\b is case-SENSITIVE: a bare "AI" in the author slot is an
        # attribution, but "Ai" is a person's name, and case-insensitive \bai\b
        # would block a real human co-author called Ai. The trailer key itself
        # still needs (?i:...) -- GitHub writes "Co-authored-by", not
        # "Co-Authored-By", so a wholly case-sensitive pattern matches nothing.
        re.compile(rf"(?i:(?:{CREDIT_TRAILER})\s*:)\s*[^\n]*\bAI\b"),
        "a co-author trailer crediting an AI author",
    ),
    (
        re.compile(
            rf"(?:Generated|Created|Written|Authored|Produced)\s+(?:with|by)\s+"
            rf"[^\n]*(?:{AI_AUTHOR})",
            re.I,
        ),
        'a "Generated with <AI>" attribution',
    ),
    (
        # Hyphenated so it cannot collide with a name: "AI-generated" is a
        # claim about authorship, "Ai Nguyen" is not.
        re.compile(r"\bAI[-\s]?(?:generated|authored|assisted|written)\b", re.I),
        'an "AI-generated" authorship marker',
    ),
    (
        # A robot emoji is only an attribution when it stands as a marker line
        # on its own. Matching it anywhere fails any text that DESCRIBES the
        # control -- which blocked a release PR whose purpose was to warn about
        # trailers, and every PR in this control's own rollout.
        #
        # Nothing is lost by narrowing it: the real trailer reads
        # "<emoji> Generated with <tool>", and the Generated/Created rule above
        # is unanchored, so it already matches with the emoji in front.
        re.compile(r"^[ \t]*\U0001F916[ \t]*$", re.M),
        "a robot emoji attribution marker line",
    ),
]

# --- END SHARED PATTERNS ---

REMEDY = """
Wilkes & Liberty work is never credited to AI -- not in commits, PR titles or
bodies, code, docs, changelogs or tickets. Work reads as authored by the human
operator.

This is NOT about hiding that AI tooling is used. Shipping a CLAUDE.md, or
naming a tool in prose, is fine. The rule is about authorship CREDIT.

To fix a COMMIT, before merging (it cannot be removed afterwards -- tags pin it):

    git rebase -i <base>          # squash or reword the offending commit(s)
    git push --force-with-lease

If the trailer came from GitHub's "Commit suggestion" or Copilot Autofix, do not
use that button. Read the suggestion, apply the edit yourself, and commit it
under your own name.

To fix an AI AUTHOR or COMMITTER IDENTITY, rewording is not enough -- the claim
is in the commit's identity fields, not its message. WHICH field is wrong
decides the fix, and the wrong one destroys credit that was correct:

  * AUTHOR is the AI (the usual case -- an agent wrote the commit):

        git rebase -i <base>          # mark the commit `edit`
        git commit --amend --reset-author --no-edit
        git rebase --continue

  * COMMITTER only, author is a human who should keep the credit (a
    server-side "Commit suggestion" applied to someone else's work).
    Do NOT use --reset-author here; it would overwrite that human with you:

        git rebase -i <base>          # mark the commit `edit`
        git commit --amend --no-edit  # re-stamps committer, author untouched
        git rebase --continue

Then `git push --force-with-lease`. The commit's content is untouched either
way. `git log --format='%an <%ae> / %cn <%ce>'` shows which field is which.

The same button is usually the cause. An agent that opens or updates a pull
request commits under its own identity, so accepting its commits wholesale
credits it in `git log` -- which is more visible than a trailer, not less.
Take the change, not the commit.

To fix a PR TITLE or BODY, just edit it here -- no history rewrite needed.
"""


def find_attribution(text: str):
    """Return the description of the first attribution shape found, or None."""
    for pattern, description in PATTERNS:
        if pattern.search(text):
            return description
    return None


# An AI name standing in the author or committer slot of a commit.
#
# The PATTERNS above only ever match an attribution *construct* -- a trailer, a
# "Generated with" footer -- because in prose a vendor name is just a word. In
# an identity field there is no construct to look for: the field IS the claim.
# `Author: copilot-swe-agent[bot]` credits an AI with authorship as plainly as
# any trailer, and more visibly, since git log and the GitHub commit list show
# the author and not the trailers.
#
# Identity matching is split in two, because the vendor list contains two very
# different kinds of word and treating them alike is wrong in both directions.
#
# UNAMBIGUOUS -- a company or product, not something a person is called. Seeing
# one in an author field is the claim by itself.
IDENTITY_UNAMBIGUOUS = (
    r"anthropic|openai|copilot|chatgpt|windsurf|aider|"
    r"github\s*copilot|swe-?agent"
)

# AMBIGUOUS -- also ordinary human given names or common words. `claude` and
# `devin` are names people have; `gemini`, `cursor`, `codex` and `llama` are
# words. Flagging these on sight would block a contributor called Claude Dupont,
# which on the published projects is an outside contribution refused for being
# named wrong. They only count alongside a marker below.
IDENTITY_AMBIGUOUS = r"claude|devin|gemini|cursor|codex|llama"

# What turns an ambiguous token into a claim: a bot/agent marker, or a noreply
# address of the kind automation commits under. `Claude <noreply@anthropic.com>`
# is caught by the unambiguous list anyway; `claude-code[bot]` is caught here.
IDENTITY_BOT_MARKER = r"\[bot\]|(?<![a-z0-9])bot(?![a-z0-9])|agent|noreply|no-reply"

# Boundaries are explicitly alphanumeric rather than `\b`, because Python's `\b`
# is built on `\w`, which counts `_` as a word character. `\bcopilot\b` does NOT
# match `copilot_swe_agent` -- the underscore is the commonest separator in bot
# handles, so the boundary intended to prevent surname false positives was also
# skipping the exact identities this check exists for.
def _bounded(alternation: str) -> re.Pattern:
    return re.compile(rf"(?<![a-z0-9])(?:{alternation})(?![a-z0-9])", re.I)


AI_IDENTITY_UNAMBIGUOUS = _bounded(IDENTITY_UNAMBIGUOUS)
AI_IDENTITY_AMBIGUOUS = _bounded(IDENTITY_AMBIGUOUS)
AI_IDENTITY_MARKER = re.compile(IDENTITY_BOT_MARKER, re.I)

# Roles are checked separately so the message can say which one is wrong.
# Both matter: an agent that authors a commit lands in the author slot, while a
# server-side "Commit suggestion" can put one in the committer slot instead.
IDENTITY_ROLES = ("author", "committer")


def find_identity_attribution(identities):
    """Return a description of the first AI identity found, or None.

    `identities` is ((author_name, author_email), (committer_name, committer_email)).

    An identity counts as an attribution when it contains an unambiguous vendor
    or product name, OR an ambiguous token together with a bot/agent marker.
    Name and email are considered as one string per role, so a marker in the
    address qualifies a token in the name -- `Claude <claude-code[bot]@...>` is
    one identity, not two unrelated fields.

    Deliberately NOT a check that the address is an @wilkesliberty.com one.
    Standing order §2 does require that of the operator, but this control also
    runs on the published projects, where an external contributor's commit is
    the point rather than a defect. A rule that fails every outside pull request
    would be removed within a week, and taking the whole control with it.
    """
    for role, (name, email) in zip(IDENTITY_ROLES, identities):
        identity = " ".join(v for v in (name, email) if v)
        if not identity:
            continue

        hit = AI_IDENTITY_UNAMBIGUOUS.search(identity)
        if hit:
            return f"an AI {role} identity ({hit.group(0)} in: {identity})"

        hit = AI_IDENTITY_AMBIGUOUS.search(identity)
        if hit and AI_IDENTITY_MARKER.search(identity):
            return (f"an AI {role} identity ({hit.group(0)} with a bot/agent "
                    f"marker, in: {identity})")
    return None


def escape_workflow_command(text: str) -> str:
    """Neutralise a value before it goes into a `::error::` annotation.

    Findings quote commit subjects and identity fields, all of which are written
    by whoever made the commit -- attacker-controlled on a fork pull request. A
    raw newline there ends the annotation and starts a new line of workflow
    output, so a crafted name could emit its own workflow commands or simply
    forge a reassuring log. GitHub's documented encoding for these three bytes.
    """
    return (text.replace("%", "%25")
                .replace("\r", "%0D")
                .replace("\n", "%0A"))


# ``` fenced block ``` or `inline span`
CODE_SPAN = re.compile(r"```.*?```|``.*?``|`[^`\n]*`", re.S)


def strip_code(markdown: str) -> str:
    """Blank markdown code spans and fenced blocks in prose before scanning.

    Mention is not use. A PR that *documents* this rule has to quote the
    strings it forbids, and in markdown the convention for quoting a literal is
    a code span. Without this, the gate fails any PR that explains the gate --
    including its own rollout, and every future edit to a CONTRIBUTING file
    that describes it. A control that cannot be described is one people route
    around.

    This is the same mention/use distinction the local commit guard draws for
    shell quoting, applied to markdown.

    Applied to the PR title and body ONLY, never to commit messages. Authorship
    credit is recorded in commit history, and that scan stays absolute -- a
    trailer inside backticks in a commit message is still a trailer.
    """
    return CODE_SPAN.sub(lambda m: " " * len(m.group(0)), markdown)


def commits_in_range(base: str, head: str):
    """Yield (sha, subject, author_name, author_email, committer_name,
    committer_email, full message) for each commit in base..head.

    **Merges are included**, deliberately, and there is no `--no-merges` here.

    This docstring used to say the opposite while the code comment below said
    "included on purpose" and the implementation included them -- a three-way
    contradiction in eight lines, left behind when the behaviour changed and
    only the comment was updated.

    This is a VENDORED file: the tests that pin this behaviour live in the
    repository it is copied from, not here. Do not read the note above as
    local coverage -- if you change this function in place, nothing in this
    repository will tell you. Change it upstream and re-vendor.

    Two reasons merges belong in the scan, and the second is why the stale
    "generated by GitHub, carries no claim of its own" reasoning was wrong:

    * a merge commit message is written by whoever merged and can carry a
      trailer like any other, and the stripper cannot cover that hole because
      it refuses to rewrite non-linear history;
    * a merge is *authored by whoever performed it*. An agent that merges a
      pull request puts its own identity on that commit, and skipping merges
      would skip exactly that case.
    """
    # NUL-delimited, not \x1e. An author name and email are supplied by whoever
    # made the commit, so they are attacker-controlled on a fork pull request:
    # a name containing the old \x1e separator split its own record into the
    # wrong number of fields, and the parser below then dropped the commit
    # silently. Two ordinary-looking choices combining into "craft a name, skip
    # the scan". NUL is the one byte git guarantees cannot appear in any of
    # these fields, so the delimiter cannot be forged.
    fields = ("%H", "%s", "%an", "%ae", "%cn", "%ce", "%B")
    out = subprocess.run(
        # -z terminates each RECORD with NUL; %x00 between fields makes the
        # field separator NUL too. Records therefore end in a doubled NUL.
        ["git", "log", "-z", "--format=" + "%x00".join(fields), f"{base}..{head}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    # -z ends each record with its own NUL, so the stream is one flat run of
    # NUL-separated fields: len(fields) per commit, exactly.
    chunks = out.split("\x00")
    if chunks and chunks[-1] == "":
        chunks.pop()

    if len(chunks) % len(fields) != 0:
        # Fail closed. The previous version skipped any record it could not
        # split and reported on whatever was left -- a gate that quietly scans
        # fewer commits than it was asked to, which is indistinguishable from a
        # clean run. If this output cannot be parsed, nothing about it is known.
        raise ValueError(
            f"unparseable git log output: {len(chunks)} field(s) is not a "
            f"multiple of {len(fields)}"
        )

    for i in range(0, len(chunks), len(fields)):
        record = chunks[i:i + len(fields)]
        # %B is trailed by git's own newline; the rest are exact.
        record[-1] = record[-1].rstrip("\n")
        yield tuple(record)


def short(rev: str) -> str:
    """Abbreviate a sha for display, but leave a ref name intact.

    Blindly slicing to 12 chars turns `origin/my-branch` into `origin/chore`,
    which reads like a real ref and is not one.
    """
    return rev[:12] if re.fullmatch(r"[0-9a-f]{40}", rev) else rev


def read_optional(path):
    """Read a title/body file. Returns (text, error).

    `error` is None on success; `text` may legitimately be empty, since a PR
    with no body is not a failure. Exactly one being set was the intent and not
    the contract -- an absent path and an empty file both return ("", None).

    An unreadable file is a wiring bug in the workflow, not a clean PR. Warning
    and returning "" would mean the title/body check silently passes whenever
    the staging step is broken -- the same "cannot see it, so call it clean"
    failure the commit-range branch already refuses. Both inputs get the same
    rule: unreadable is a failure, never a pass.
    """
    if not path:
        return "", None
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read(), None
    except OSError as exc:
        return "", f"could not read {path}: {exc}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="base sha of the PR")
    parser.add_argument("--head", required=True, help="head sha of the PR")
    parser.add_argument("--title-file", help="file containing the PR title")
    parser.add_argument("--body-file", help="file containing the PR body")
    args = parser.parse_args()

    findings = []

    try:
        commits = list(commits_in_range(args.base, args.head))
    except subprocess.CalledProcessError as exc:
        # Almost always a shallow clone: the workflow needs fetch-depth: 0.
        # Fail loudly -- a gate that cannot see the commits must not report
        # green, or it silently stops being a gate.
        print("::error::could not read the commit range. Does the checkout use "
              "fetch-depth: 0?")
        print(exc.stderr or "", file=sys.stderr)
        return 1

    for sha, subject, an, ae, cn, ce, message in commits:
        description = find_attribution(message)
        if description:
            findings.append(f"commit {short(sha)} ({subject}) carries {description}")

        identity = find_identity_attribution(((an, ae), (cn, ce)))
        if identity:
            findings.append(f"commit {short(sha)} ({subject}) carries {identity}")

    for label, path in (("PR title", args.title_file), ("PR body", args.body_file)):
        text, error = read_optional(path)
        if error:
            # Reported as a finding rather than an immediate exit, so a run
            # still lists every problem it found in one pass.
            findings.append(f"the {label} could not be checked: {error}")
            continue
        if text:
            description = find_attribution(strip_code(text))
            if description:
                findings.append(f"the {label} carries {description}")

    print(f"Scanned {len(commits)} commit(s) in "
          f"{short(args.base)}..{short(args.head)}.")

    if not findings:
        print("No AI attribution found.")
        return 0

    for finding in findings:
        print(f"::error::{escape_workflow_command(finding)}")
    print(REMEDY)
    return 1


if __name__ == "__main__":
    sys.exit(main())
