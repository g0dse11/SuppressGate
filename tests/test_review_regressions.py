"""Regressions found during the v0.1 code review."""
from __future__ import annotations

from contextlib import redirect_stdout, redirect_stderr
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
            git(root, "add", ".suppressgate.toml")
            git(root, "commit", "-qm", "commit policy to trusted baseline")
            nested = root / "deep" / "inside"
            nested.mkdir(parents=True)
            output = StringIO()
            with redirect_stdout(output):
                exit_code = main(["check", "--repo", str(nested), "--base", "HEAD", "--format", "json"])
            report = json.loads(output.getvalue())
            self.assertEqual(exit_code, 1)
            self.assertEqual(report["rejected"], 1)
            self.assertIn("PROTECTED_RULE_SUPPRESSED", report["changes"][0]["checks"])


class TrustedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        git(self.root, "init", "-q")
        git(self.root, "config", "user.email", "test@example.com")
        git(self.root, "config", "user.name", "Example Test")
        (self.root / "source.py").write_text("pass\n", encoding="utf-8")
        (self.root / ".suppressgate.toml").write_text(
            '[policy]\nrequire_rule = true\nrequire_reason = true\n'
            '[policy.protected]\nruff = ["S608"]\n', encoding="utf-8"
        )
        git(self.root, "add", ".")
        git(self.root, "commit", "-qm", "base policy")

    def run_cli(self, *extra):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["check", "--repo", str(self.root), "--base", "HEAD", "--format", "json", *extra])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_unmodified_base_policy_enforces_protected_rule(self):
        (self.root / "source.py").write_text(
            "danger()  # noqa: S608 -- claimed safe\n", encoding="utf-8"
        )
        code, output, error = self.run_cli()
        self.assertEqual(code, 1)
        self.assertEqual(error, "")
        report = json.loads(output)
        self.assertEqual(report["rejected"], 1)
        self.assertIn("PROTECTED_RULE_SUPPRESSED", report["changes"][0]["checks"])

    def test_crlf_checkout_matches_lf_policy_in_base(self):
        # Windows Git normally checks out CRLF while Git objects contain LF.
        policy = self.root / ".suppressgate.toml"
        # Explicitly store an LF version in Git, regardless of the host OS's
        # default text-file line endings or the user's Git autocrlf setting.
        original = policy.read_bytes().replace(b"\r\n", b"\n")
        policy.write_bytes(original)
        git(self.root, "-c", "core.autocrlf=true", "add", ".suppressgate.toml")
        git(self.root, "commit", "--allow-empty", "-qm", "store LF policy baseline")
        base_policy = subprocess.run(
            ["git", "-C", str(self.root), "show", "HEAD:.suppressgate.toml"],
            check=True, capture_output=True,
        ).stdout
        self.assertEqual(base_policy, original)
        policy.write_bytes(original.replace(b"\n", b"\r\n"))
        (self.root / "source.py").write_text(
            "danger()  # noqa: S608 -- claimed safe\n", encoding="utf-8"
        )
        code, output, error = self.run_cli()
        self.assertEqual(code, 1, error)
        self.assertEqual(error, "")
        self.assertIn("PROTECTED_RULE_SUPPRESSED", json.loads(output)["changes"][0]["checks"])

    def test_crlf_checkout_does_not_hide_actual_policy_change(self):
        policy = self.root / ".suppressgate.toml"
        policy.write_bytes(
            policy.read_bytes().replace(b"\r\n", b"\n")
            .replace(b"require_reason = true", b"require_reason = false")
            .replace(b"\n", b"\r\n")
        )
        code, output, error = self.run_cli()
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("differs from base commit", error)

    def test_relaxed_policy_in_same_change_cannot_bypass_gate(self):
        (self.root / ".suppressgate.toml").write_text(
            '[policy]\nrequire_rule = false\nrequire_reason = false\n', encoding="utf-8"
        )
        (self.root / "source.py").write_text("danger()  # noqa\n", encoding="utf-8")
        code, output, error = self.run_cli()
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("differs from base commit", error)

    def test_removed_policy_is_rejected(self):
        (self.root / ".suppressgate.toml").unlink()
        code, output, error = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn("differs from base commit", error)

    def test_new_untracked_policy_cannot_affect_review(self):
        git(self.root, "rm", "-q", ".suppressgate.toml")
        git(self.root, "commit", "-qm", "remove policy")
        (self.root / ".suppressgate.toml").write_text(
            '[policy]\nrequire_rule = false\nrequire_reason = false\n', encoding="utf-8"
        )
        code, output, error = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn("differs from base commit", error)

    def test_explicit_policy_in_repo_is_checked_against_base(self):
        (self.root / "custom.toml").write_text(
            '[policy]\nrequire_rule = false\nrequire_reason = false\n', encoding="utf-8"
        )
        code, output, error = self.run_cli("--config", str(self.root / "custom.toml"))
        self.assertEqual(code, 2)
        self.assertIn("differs from base commit", error)

    def test_explicit_in_repo_policy_via_external_lexical_alias_is_rejected(self):
        # Path.absolute() can retain '..' (and Windows may use short/long path
        # aliases).  A path that physically lies inside the checkout must not
        # be treated as an operator-controlled external policy.
        (self.root / "custom.toml").write_text(
            '[policy]\nrequire_rule = false\nrequire_reason = false\n', encoding="utf-8"
        )
        with tempfile.TemporaryDirectory(dir=self.root.parent) as sibling:
            aliased = Path(sibling) / ".." / self.root.name / "custom.toml"
            self.assertTrue(aliased.is_file())
            code, output, error = self.run_cli("--config", str(aliased))
        self.assertEqual(code, 2, (output, error))
        self.assertIn("differs from base commit", error)

    def test_explicit_outside_repo_policy_is_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            external = Path(directory) / "trusted.toml"
            external.write_text('[policy]\nrequire_rule = false\nrequire_reason = false\n', encoding="utf-8")
            (self.root / "source.py").write_text("danger()  # noqa\n", encoding="utf-8")
            code, output, error = self.run_cli("--config", str(external))
            self.assertEqual(code, 0)
            self.assertEqual(error, "")
            self.assertEqual(json.loads(output)["total_changes"], 1)


if __name__ == "__main__":
    unittest.main()
