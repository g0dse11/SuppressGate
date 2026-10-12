"""Regressions found during the v0.1 code review."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from suppressgate.cli import main
from suppressgate.core import Policy, _policy_checks, scan_source


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


class PolicySafetyRegressionTests(unittest.TestCase):
    def test_blanket_suppression_cannot_bypass_protected_rules(self):
        item = scan_source(b"risky()  # noqa -- locally approved\n", "sample.py")[0]
        policy = Policy(require_rule=False, protected={"ruff": frozenset({"S608"})})
        self.assertIn("PROTECTED_RULE_SUPPRESSED", _policy_checks(item, policy))

    def test_nested_repo_path_still_loads_top_level_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git(root, "init", "-q")
            git(root, "config", "user.email", "test@example.com")
            git(root, "config", "user.name", "Example Test")
            (root / "source.py").write_text("pass\n", encoding="utf-8")
            git(root, "add", ".")
            git(root, "commit", "-qm", "base")
            (root / ".suppressgate.toml").write_text(
                '[policy.protected]\nruff = ["S608"]\n', encoding="utf-8"
            )
            (root / "source.py").write_text(
                "danger()  # noqa: S608 -- a reason\n", encoding="utf-8"
            )
            nested = root / "deep" / "inside"
            nested.mkdir(parents=True)
            output = StringIO()
            with redirect_stdout(output):
                exit_code = main(["check", "--repo", str(nested), "--base", "HEAD", "--format", "json"])
            report = json.loads(output.getvalue())
            self.assertEqual(exit_code, 1)
            self.assertEqual(report["rejected"], 1)
            self.assertIn("PROTECTED_RULE_SUPPRESSED", report["changes"][0]["checks"])


if __name__ == "__main__":
    unittest.main()
