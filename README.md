# SuppressGate

**Status: v0.1.1a1 alpha candidate.** Tested on Python 3.11–3.14 on Windows and Ubuntu in GitHub Actions. This is **not** a security guarantee or an independently audited product.

SuppressGate helps reviewers notice when a Git change introduces or modifies a Python lint/security suppression. Rather than only counting suppressions, it associates each directive with a **source-code token signature**. Removing an old `# noqa: S608` while adding one to *different code* is reported, even if the total number stays the same.

SuppressGate does **not** replace Ruff, Bandit or Semgrep, run those scanners, or verify that a developer's justification is truthful. Use it as an additional review signal, not a substitute for code review or security scanning.

## Quick start

**Requirements:** Python 3.11+ and Git for revision comparisons. No third-party runtime Python dependencies, account, or hosted service.

When the GitHub repository is publicly accessible, clone and install it:

```bash
git clone https://github.com/g0dse11/SuppressGate.git
cd SuppressGate
python -m pip install .
suppress-gate --help
```

Alternatively, download the repository ZIP from GitHub, extract it, and run `python -m pip install .` inside the extracted project directory. **SuppressGate is not yet published on PyPI**; do not assume `pip install suppressgate` works.

Run a demonstration that creates its own temporary Git repository:

```bash
python examples/demo.py
```

Developers who want to run the test suite can use:

```bash
python -m unittest discover -s tests -v
```

On a Python project, from **that project's Git repository root**, run:

```bash
suppress-gate scan .
suppress-gate check --base HEAD
suppress-gate check --base origin/main --format json
```

`scan` inventories Python suppressions without needing Git. `check` compares the current working tree, including staged and unstaged changes, with the named Git revision. Use `origin/main` only if that ref exists and is current. `HEAD` means your latest local commit. From another directory, use `suppress-gate check --repo /path/to/repo --base HEAD`.

**Exit codes:** `0` = policy passed; `1` = policy violations; `2` = check could not reliably complete (for example, invalid Git ref, unreadable source or invalid configuration).

## Supported directives (alpha)

```python
# `-- explanation` is SuppressGate's convention for a justification.
query = f"SELECT * FROM users WHERE id = {user_id}"  # noqa: S608 -- reviewed false positive
subprocess.run(cmd, shell=True)  # nosec B602 -- required for a controlled test
something()  # nosemgrep: python.lang.security.some-rule -- safe because input is fixed
```

- `# noqa[: RULE[, RULE...]]` — Ruff/Flake8-style suppressions
- `# nosec [RULE[, RULE...]]` — Bandit suppressions
- `# nosemgrep[: RULE[, RULE...]]` — Semgrep suppressions

SuppressGate uses Python's **COMMENT tokens** to avoid treating strings and docstrings as directives. A standalone suppression is associated with the next non-comment line within three lines. It interprets `--` as a justification separator. This convention and the examples **are not guaranteed to be valid for every upstream scanner**; verify that the scanner really honours the directive before introducing it.

## Local policy

By default, **new or modified** suppressions require explicit rule IDs and a non-empty `-- justification` comment. Suppressions already present in the base revision are grandfathered in.

Copy `.suppressgate.toml.example` to `.suppressgate.toml` in the target repository to configure restrictions:

```toml
[policy]
require_rule = true
require_reason = true

[policy.protected]
ruff = ["S608"]
bandit = ["B602"]
```

Blanket suppressions for a scanner with protected rules are rejected, even if `require_rule = false`, since they could silence protected rules. The tool loads the policy from the Git repository root even if invoked from a nested directory.

New suppressions with a present justification are shown as **`REVIEW`** and do not fail CI. New suppressions with a missing reason, missing rule ID, or protected rule are shown as **`REJECT`** and cause a failure. A `REVIEW` result does **not** mean a human has approved the exception.

## Example: what a count-only check misses

Base revision:

```python
old_query()  # noqa: S608 -- legacy exception
```

Proposed change:

```python
new_query()  # noqa: S608
```

Both versions contain one suppression, but the new occurrence has different associated code and is flagged. Merely moving an unchanged suppressed statement to another line does not necessarily count as new. Recognised Git file renames are also handled.

## Using it in CI

SuppressGate can run on pull requests. The repository's `.github/workflows/suppressgate-pr.yml` demonstrates its **own** integration and has been tested using a deliberately failing pull request followed by a correction.

For another repository, check out sufficient Git history (`fetch-depth: 0`), install SuppressGate from a reviewed and pinned version, and compare against the pull request's actual base commit—not an assumed default branch. Start with a non-required check until you have assessed false positives in your repository.

The tool reads source files and Git history; it does not execute Python project files, rewrite source files or upload results to a hosted SuppressGate service.

## Important limitations

- **Python `.py` and `.pyi` only**, and inline/comment suppressions only; no JavaScript or TypeScript.
- The tool detects suppression directives, **not** the actual Ruff/Bandit/Semgrep findings they hide. Changes to the diagnostic without changes to the associated code tokens may be missed. This is **not** a sound security guarantee.
- Identical suppressed statements in the same file cannot always be distinguished when one is removed and another identical one is added. Fingerprint matching is a heuristic, not semantic or AST-aware analysis.
- No suppression auditing in configuration files, and no file-wide/region directive support.
- No verification that a justification is true, no expiry enforcement, auto-fixes, SARIF, dashboard, hosted service or AI.
- Does not validate scanner-specific syntax or rule catalogue entries; rule IDs are parsed as text.
- May be slow on large repositories; the prototype is not tuned for monorepos. The working-tree side includes untracked files; tracked ignored/generated files are not excluded automatically.
- A non-existent Git revision is an error. SuppressGate does not audit policy-file tampering; protect your CI workflow, default branch and repository configuration independently.

## Help validate the alpha

If you work with Ruff, Bandit or Semgrep, try SuppressGate on a **real pull request** and share: whether it found a meaningful new suppression, any false positives, any missed changes, and whether you would choose to keep the check in your workflow.

Feedback and bug reports: [GitHub Issues](https://github.com/g0dse11/SuppressGate/issues).

The first adoption test is deliberately modest: show it to five relevant developers and continue investing only if at least two independently choose to test it in real repositories. If existing tools solve their needs, prefer improving those tools over adding features here.

## License

MIT — see [LICENSE](LICENSE).
