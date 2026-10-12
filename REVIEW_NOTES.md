# SuppressGate v0.1 code review — 12 October 2026

Review of the original SuppressGate v0.1.0.dev0 source. This is a **local prototype**, not a security certification, third-party audit, or production release.

## Confirmed policy-enforcement defects corrected

1. **Root policy silently skipped when invoked from a Git subfolder.**
   The CLI previously loaded `.suppressgate.toml` relative to `--repo` (or the current directory) **before** discovering the actual Git root, although the scan then examined the whole repository. A stricter root policy could be silently ignored. The reviewed CLI determines Git root *before* loading the default policy. Regression: `test_nested_repo_path_still_loads_top_level_policy`.

2. **Blanket suppression could evade configured protected rules when `require_rule = false`.**
   A `# noqa -- reason` suppresses all Ruff rules, including a protected rule, but previously the protected-rules check iterated the empty explicit ID list. The reviewed policy now rejects a blanket suppression of a tool that has any protected rules configured. Regression: `test_blanket_suppression_cannot_bypass_protected_rules`.

The two regression tests were confirmed **failing** against the original source before the corrections and **passing** after.

## Test evidence

- Existing test suite: 24/24 passed.
- New regression tests: 2/2 passed.
- Combined: 26/26 passed using Python standard-library `unittest` in the test environment.
- Manual tests of a demo and Git worktree were previously carried out for the original version. A passing automated suite cannot prove accuracy across all repositories.

## Remaining limitations / pre-public-alpha precautions

- Fingerprints use source token signatures. Moving an *identical* suppressed statement to a different location in the same file can evade a new-suppression finding; editing the surrounding context may also change diagnostic significance without changing the signature. This is **not** a proof that suppressions are safe or unchanged.
- Only Python `.py`/`.pyi` comment forms `noqa`, `nosec`, and `nosemgrep` are recognised. Entire-file suppressions (`# ruff: noqa`) and config-level ignores are not covered. This is an intentionally narrow scope, but must be explicit when recruiting testers.
- Rule IDs are tokenised but **not checked** against Ruff/Bandit/Semgrep's accepted current rule catalogues. Presence of an ID and human-readable reason is only a formatting policy, not validation or approval.
- The tool's `-- justification` convention has not been compatibility-tested against the upstream scanners for every rule/comment syntax; validate it before enforcing CI.
- A change to `.suppressgate.toml` in the same branch can weaken the policy unless CI stores/enforces trusted policy separately. Secure branch/CI configuration remains the user's responsibility.
- A full baseline and worktree scan can be slow on large Python monorepos; renamed files with low Git similarity may be presented as new files.

## Next quality gate

Trial on an actual pull request **containing** newly introduced suppressions. Cross-check results with a human review and the relevant scanner, recording false positives and missed suppressions. Do not roll this out as a blocking security gate across untested repositories.
