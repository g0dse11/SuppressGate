from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

from suppressgate.cli import main
from suppressgate.core import (
    GateError, Policy, _compare, check_git, load_policy,
    scan_directory, scan_source,
)


def git(root: Path, *arguments: str) -> None:
    subprocess.run(["git", "-C", str(root), *arguments], check=True, capture_output=True)


class SourceTests(unittest.TestCase):
    def scan(self, source: str):
        return scan_source(source.encode(), "sample.py")

    def test_excludes_strings_and_docstrings(self):
        code = (
            'doc = "# noqa: S608"\n'
            'other = """\n# nosec B602\n# nosemgrep: rule-id\n"""\n'
            'real_call()  # noqa: S608 -- accepted for unit test\n'
        )
        result = self.scan(code)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].kind, "ruff")
        self.assertEqual(result[0].rules, ("S608",))

    def test_descriptive_comment_does_not_create_suppression(self):
        source = "# This is an example of the string '# noqa: S608' in docs.\n"
        self.assertEqual(self.scan(source), [])

    def test_type_comment_followed_by_directive(self):
        source = "value = 1  # type: ignore # nosec B602 -- reviewed exception\n"
        items = self.scan(source)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].kind, "bandit")

    def test_bare_directive_has_no_rule_or_reason(self):
        result = self.scan("call()  # noqa\n")
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0].rules)
        self.assertEqual(result[0].reason, "")

    def test_nosec_and_nosemgrep(self):
        code = (
            "run()  # nosec B602,B607 -- sandboxed test\n"
            "run()  # nosemgrep: python.lang.security.danger -- reviewed false positive\n"
        )
        result = self.scan(code)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].rules, ("B602", "B607"))
        self.assertEqual(result[1].rules, ("python.lang.security.danger",))
        self.assertEqual(result[1].reason, "reviewed false positive")

    def test_standalone_nosemgrep_anchor(self):
        source = "# nosemgrep: test.rule -- documented acceptance\ncall()\n"
        result = self.scan(source)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].line, 1)
        self.assertIn("call", result[0].anchor)

    def test_line_moves_preserve_identity(self):
        a = self.scan("x = foo(1)  # noqa: F401 -- previously approved\n")[0]
        b = self.scan("\n\n  x=foo(1) # noqa: F401 -- previously approved\n")[0]
        self.assertEqual(a.fingerprint, b.fingerprint)

    def test_same_count_swap_is_detected(self):
        before = self.scan("old_call()  # noqa: S608 -- old exception\n")
        after = self.scan("new_call()  # noqa: S608 -- new exception\n")
        changes = _compare(before, after)
        self.assertEqual(len(before), len(after))
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0][0], "new")

    def test_duplicate_reason_reordering_does_not_double_report(self):
        before = self.scan(
            "call() # noqa: F401 -- first reason\n"
            "call() # noqa: F401 -- second reason\n"
        )
        after = self.scan(
            "call() # noqa: F401 -- a new reason\n"
            "call() # noqa: F401 -- first reason\n"
        )
        changes = _compare(before, after)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0][0], "modified")

    def test_justification_removal_is_change(self):
        before = self.scan("call()  # noqa: F401 -- legitimate exception\n")
        after = self.scan("call()  # noqa: F401\n")
        changes = _compare(before, after)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0][0], "modified")

    def test_duplicate_same_line_only_counts_new_instance(self):
        before = self.scan("call() # noqa: F401 -- accepted\n")
        after = self.scan("call() # noqa: F401 -- accepted\ncall() # noqa: F401 -- accepted\n")
        self.assertEqual(len(_compare(before, after)), 1)

    def test_unicode_encoding_cookie(self):
        source = b'# coding: latin-1\nprint("caf\xe9")  # noqa: E501 -- accepted reason\n'
        self.assertEqual(len(scan_source(source, "legacy.py")), 1)

    def test_incomplete_multiline_string_fails_closed(self):
        with self.assertRaises(GateError):
            self.scan('"""unfinished\n# noqa: S608\n')

    def test_non_git_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.py").write_text("call() # noqa: F401 -- approved\n")
            (root / ".venv").mkdir()
            (root / ".venv" / "hidden.py").write_text("call() # noqa\n")
            self.assertEqual(len(scan_directory(root)), 1)


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        git(self.root, "init", "-q")
        git(self.root, "config", "user.email", "test@example.com")
        git(self.root, "config", "user.name", "Example Test")
        (self.root / "module.py").write_text("old_call()  # noqa: S608 -- previously accepted\n")
        git(self.root, "add", ".")
        git(self.root, "commit", "-qm", "base")

    def tearDown(self):
        self.temporary.cleanup()

    def test_detects_same_count_swap_in_real_git_repo(self):
        (self.root / "module.py").write_text("new_call()  # noqa: S608\n")
        findings, _ = check_git(self.root, "HEAD", Policy())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].change, "new")
        self.assertIn("MISSING_JUSTIFICATION", findings[0].checks)
        self.assertTrue(findings[0].rejected)

    def test_unchanged_annotation_does_not_regress(self):
        (self.root / "module.py").write_text("# File header\n\nold_call() # noqa: S608 -- previously accepted\n")
        findings, _ = check_git(self.root, "HEAD", Policy())
        self.assertEqual(findings, [])

    def test_remove_reason_rejected(self):
        (self.root / "module.py").write_text("old_call()  # noqa: S608\n")
        findings, _ = check_git(self.root, "HEAD", Policy())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].change, "modified")
        self.assertIn("MISSING_JUSTIFICATION", findings[0].checks)

    def test_changed_rule_counts_new(self):
        (self.root / "module.py").write_text("old_call()  # noqa: S602 -- previously accepted\n")
        findings, _ = check_git(self.root, "HEAD", Policy())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].change, "new")

    def test_renamed_source_preserves_old_suppressions(self):
        git(self.root, "mv", "module.py", "renamed.py")
        findings, _ = check_git(self.root, "HEAD", Policy())
        self.assertEqual(findings, [])

    def test_new_untracked_file_detected(self):
        (self.root / "new_file.py").write_text("foo() # noqa: F401\n")
        findings, _ = check_git(self.root, "HEAD", Policy())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].suppression.path, "new_file.py")

    def test_policy_protected_rule(self):
        (self.root / ".suppressgate.toml").write_text(
            '[policy]\nrequire_rule = true\nrequire_reason = true\n'
            '[policy.protected]\nruff = ["S608"]\n'
        )
        (self.root / "module.py").write_text(
            "old_call() # noqa: S608 -- previously accepted\n"
            "new_call() # noqa: S608 -- accepted reason for new usage\n"
        )
        policy = load_policy(self.root)
        findings, _ = check_git(self.root, "HEAD", policy)
        self.assertEqual(len(findings), 1)
        self.assertIn("PROTECTED_RULE_SUPPRESSED", findings[0].checks)
        self.assertTrue(findings[0].rejected)

    def test_justified_new_annotation_is_informational(self):
        (self.root / "module.py").write_text(
            "old_call() # noqa: S608 -- previously accepted\n"
            "safe_call() # noqa: F401 -- approved for demonstration\n"
        )
        findings, _ = check_git(self.root, "HEAD", Policy())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].checks, ("NEW_SUPPRESSION",))
        self.assertFalse(findings[0].rejected)

    def test_cli_json_and_exit_codes(self):
        (self.root / "module.py").write_text("new_call() # noqa: S608\n")
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["check", "--repo", str(self.root), "--base", "HEAD", "--format", "json"])
        self.assertEqual(code, 1)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["total_changes"], 1)
        self.assertEqual(report["rejected"], 1)
        self.assertFalse(report["passed"])
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["check", "--repo", str(self.root), "--base", "NONEXISTENT"])
        self.assertEqual(code, 2)
        self.assertIn("SuppressGate error", stderr.getvalue())

    def test_invalid_config_fails_closed(self):
        (self.root / ".suppressgate.toml").write_text('[policy]\nrequire_rule = "no"\n')
        with self.assertRaises(GateError):
            load_policy(self.root)


if __name__ == "__main__":
    unittest.main()
