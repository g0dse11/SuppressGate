"""Self-contained local demo of a same-count suppression swap.

Run from an installed or source-configured SuppressGate environment:
    python examples/demo.py

Creates a temporary Git repository, never touches your existing projects.
"""

from pathlib import Path
import subprocess
import sys
import tempfile


def command(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="suppressgate-demo-") as directory:
        root = Path(directory)
        for args in [
            ("git", "init", "-q"),
            ("git", "config", "user.email", "demo@example.invalid"),
            ("git", "config", "user.name", "Demo"),
        ]:
            result = command(*args, cwd=root)
            if result.returncode:
                print(result.stderr, file=sys.stderr)
                return 2
        target = root / "example.py"
        target.write_text("old_query()  # noqa: S608 -- reviewed legacy exception\n")
        command("git", "add", "example.py", cwd=root)
        commit = command("git", "commit", "-qm", "Initial suppression baseline", cwd=root)
        if commit.returncode:
            print(commit.stderr, file=sys.stderr)
            return 2
        target.write_text("new_query()  # noqa: S608\n")
        print("Base:        old_query()  # noqa: S608 -- reviewed legacy exception")
        print("Working tree: new_query()  # noqa: S608")
        print("Both versions have one suppression. Here is the check:\n")
        checked = command(sys.executable, "-m", "suppressgate", "check", "--base", "HEAD", cwd=root)
        print(checked.stdout)
        if checked.stderr:
            print(checked.stderr, file=sys.stderr)
        if checked.returncode != 1:
            print(f"Unexpected result code: {checked.returncode}", file=sys.stderr)
            return 2
        print("Demo succeeded: a same-count swap was identified and rejected.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
