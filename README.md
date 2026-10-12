# SuppressGate — suppression-review prototype

**Status: locally reviewed proof of concept (v0.1.1 dev), not a released security product.**

SuppressGate helps reviewers notice when a Git change introduces or modifies a
Python lint/security suppression. Unlike a count-only suppression ratchet, it
uses the associated **source-code token signature** to distinguish suppressions:
fixing an old `# noqa: S608` and adding another to *different code* is reported,
even if the overall number remains the same.

This is **not** a replacement for Ruff, Bandit or Semgrep. It does **not** run
those scanners or prove that a justification is truthful. The working name is
not cleared for branding/package-name availability.

## Try it (Python 3.11+, Git)

Unzip and open a terminal in the `SuppressGate` folder:

```bash
python -m pip install -e .
suppress-gate scan .
python -m unittest discover -s tests -v
```

No nonstandard **runtime** Python dependencies, no accounts, no network calls.
For a safe end-to-end demonstration that creates a **temporary** Git repo:

```bash
python examples/demo.py
```

Editable installation with pip may require build tooling; the source itself
runs with only the standard library:

```bash
PYTHONPATH=src python -m suppressgate scan .    # Linux/macOS
```

On Windows PowerShell, use `$env:PYTHONPATH = 'src'` and then
`python -m suppressgate scan .`.

To evaluate an existing **Git** repository (including staged and unstaged
working-tree files), run from the repository root:

```bash
suppress-gate check --base HEAD
suppress-gate check --base origin/main --format json
```

Or from another directory: `suppress-gate check --repo /path/to/repo --base HEAD`.
The `origin/main` branch must actually exist; `HEAD` always refers to your last
local commit. Exit status: **0** = policy passed; **1** = policy violations;
**2** = cannot confidently complete check (bad Git ref, unreadable source,
invalid configuration, etc.).

## Supported annotation forms (v0 prototype)

```python
# `-- explanation` is SuppressGate's explicit convention for justifications.
query = f"SELECT * FROM users WHERE id = {user_id}"  # noqa: S608 -- reviewed false positive
subprocess.run(cmd, shell=True)  # nosec B602 -- required for a controlled test
something()  # nosemgrep: python.lang.security.some-rule -- safe because input is fixed
```

- `# noqa[: RULE[, RULE...]]` → Ruff / Flake8-style suppressions
- `# nosec [RULE[, RULE...]]` → Bandit suppressions
- `# nosemgrep[: RULE[, RULE...]]` → Semgrep suppressions

The parser recognises Python **COMMENT tokens**, not matching-looking text inside
strings or docstrings. A standalone suppression is associated with the next
non-comment line within three lines. We consider `--` the justification
separator; each scanner has its own syntax, so validate compatibility in your
actual projects before putting the gate in CI.

## Local policy

Without a config file, **new/modified** suppressions require explicit rule IDs
and a nonempty `-- justification` comment. Existing suppressions in the base
revision are grandfathered in. Copy `.suppressgate.toml.example` to
`.suppressgate.toml` in the target repo to protect particular rules:

```toml
[policy]
require_rule = true
require_reason = true

[policy.protected]
ruff = ["S608"]
bandit = ["B602"]
```

When protected-rule restrictions are configured, blanket suppressions of that
tool are rejected even if `require_rule = false`, because a blanket suppression
might silence a protected rule. Running `check` from a nested directory still
loads the `.suppressgate.toml` policy from the Git repository root.

A valid, justified new annotation is printed as `REVIEW` and does not fail CI;
a missing rule, missing reason or protected rule is `REJECT` and fails.
`NEW_SUPPRESSION` is always recorded in the structured findings so every
change can be reviewed. Justifications are only checked for **presence**, not
truth or quality.

## Example: what count-only gates miss

Base revision:

```python
old_query()  # noqa: S608 -- legacy exception
```

Working tree:

```python
new_query()  # noqa: S608
```

Both versions have one suppression; a count-only gate can pass. SuppressGate
reports the new `new_query()` occurrence and rejects it for a missing reason.
If the code is simply moved to another line unchanged, the fingerprint remains
stable. Recognised Git file renames are also handled.

## CI, safely

This tool reads your source and Git history; it does not execute project files,
modify source or send data anywhere. In a GitHub Actions workflow, first use
`actions/checkout` with sufficient history (`fetch-depth: 0`), set up Python,
install this tool from a reviewed/pinned source, then run
`check --base origin/main`. Do not make a blocking gate mandatory before
validating it on your own repository.

## Fixed prototype boundaries / limitations

- **Python `.py` and `.pyi` only**, and inline/comment suppressions only. No JS/TS.
- No understanding of actual Ruff/Bandit/Semgrep findings. It detects directives,
  not the suppressed diagnostic's identity. A source change that keeps the same
  code tokens may hide a changed diagnostic; this is **not** a sound security
  guarantee.
- Identical suppressed statements in the same file cannot always be distinguished
  when one is removed and another identical one is introduced. Token-signature
  matching is a heuristic, not semantic or AST-aware fingerprinting.
- No monitoring of suppression options in config files, or file-wide/region directives.
- No automatic justification verification, expiry enforcement, hosted service,
  dashboard, AI, SARIF export, marketplace action or auto-fixes.
- Does not verify syntax accepted by the upstream scanners. Rule selectors
  are parsed as text, not validated against each scanner's current rule catalogue.
- Parses the repository's full tracked Python history at the chosen base; the
  prototype is not optimised for large monorepos. Untracked files are included
  in the working-tree side and tracked ignored/generated files are not exempt.
- A Git ref that does not exist is a hard error. This prototype does not audit
  policy-file tampering; secure CI config/branch protections are up to users.

## Validation criterion

Before broadening the tool, show its actual output to 5 developers familiar
with Ruff/Bandit. Keep going only if 2 want to **test it on real repositories**
and the prototype's fingerprints survive representative PR changes. If existing
tools solve their problem, stop or contribute upstream instead.

See `tests/` for same-count swap, unchanged/moved suppressions, reason changes,
strings, protected rules and real Git revision comparisons.
