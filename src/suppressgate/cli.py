"""The SuppressGate command line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .core import GateError, _git_root, check_git, load_review_policy, scan_directory


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="suppress-gate",
        description="Review new lint/security suppressions in Python Git changes.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Inventory Python suppressions (no Git needed)")
    scan.add_argument("path", nargs="?", default=".", help="Source directory")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    check = sub.add_parser("check", help="Review suppressions added/changed since a Git revision")
    check.add_argument("--base", required=True, help="Git revision, e.g. origin/main or HEAD")
    check.add_argument("--repo", default=".", help="Path to Git repository")
    check.add_argument("--config", help="Policy TOML path; repository policy changes are rejected")
    check.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "scan":
            items = scan_directory(Path(args.path))
            if args.format == "json":
                print(json.dumps({"suppressions": [item.to_dict() for item in items], "total": len(items)}, indent=2))
            else:
                print(f"SuppressGate inventory: {len(items)} Python suppression(s)")
                for item in items:
                    rules = ", ".join(item.rules) or "<all rules>"
                    reason = item.reason or "<no justification>"
                    print(f"  {item.path}:{item.line}  {item.kind} [{rules}]  {reason}")
            return 0

        # Always discover policy from the Git repository root, even when a user
        # invokes `check` in a nested source directory. Otherwise the default
        # policy silently overrides a stricter repository-root policy.
        root = _git_root(Path(args.repo).resolve())
        policy = load_review_policy(root, args.base, Path(args.config).absolute() if args.config else None)
        findings, commit = check_git(root, args.base, policy)
        blocked = sum(f.rejected for f in findings)
        if args.format == "json":
            print(json.dumps({
                "base_commit": commit,
                "changes": [finding.to_dict() for finding in findings],
                "total_changes": len(findings),
                "rejected": blocked,
                "passed": blocked == 0,
            }, indent=2))
        else:
            print(f"SuppressGate check against {args.base} ({commit[:12]})")
            for item in findings:
                source = item.suppression
                state = "REJECT" if item.rejected else "REVIEW"
                print(f"\n[{state}] {source.path}:{source.line}  {item.change.upper()} {source.kind}")
                print(f"  Rules: {', '.join(source.rules) or '<all rules>'}")
                print(f"  Reason: {source.reason or '<missing>'}")
                print(f"  Checks: {', '.join(item.checks)}")
                print(f"  ID: {source.fingerprint}")
            print(f"\nResult: {'FAILED' if blocked else 'PASSED'} | {len(findings)} new/modified, {blocked} rejected")
        return 1 if blocked else 0
    except GateError as exc:
        print(f"SuppressGate error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
