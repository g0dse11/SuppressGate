"""SuppressGate's small, read-only Python suppression review engine.

This is a proof of concept, not a Python security scanner. It compares the
identity of suppression annotations; it does not determine whether a suppressed
finding is a real vulnerability or whether a justification is true.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tokenize
import tomllib
from typing import Any


_DIRECTIVE = re.compile(r"#\s*(noqa|nosec|nosemgrep)\b", re.IGNORECASE)
_CODE = re.compile(r"\s+")
_SOURCE_SUFFIXES = {".py", ".pyi"}
_SKIP_FOLDERS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox"}


class GateError(Exception):
    """A source, Git, or configuration failure; never quietly pass a check."""


@dataclass(frozen=True)
class Suppression:
    path: str
    line: int
    kind: str
    rules: tuple[str, ...]
    reason: str
    anchor: str
    comment: str
    fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"rules": list(self.rules)}


@dataclass(frozen=True)
class Finding:
    change: str  # 'new' or 'modified'
    suppression: Suppression
    checks: tuple[str, ...]  # NEW_SUPPRESSION, MISSING_*, PROTECTED_*

    @property
    def rejected(self) -> bool:
        return any(check != "NEW_SUPPRESSION" for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "change": self.change,
            "suppression": self.suppression.to_dict(),
            "checks": list(self.checks),
            "rejected": self.rejected,
        }


@dataclass(frozen=True)
class Policy:
    require_rule: bool = True
    require_reason: bool = True
    protected: dict[str, frozenset[str]] | None = None

    def protected_rules(self, kind: str) -> frozenset[str]:
        return (self.protected or {}).get(kind, frozenset())


def load_policy(root: Path, config: Path | None = None) -> Policy:
    path = config if config is not None else root / ".suppressgate.toml"
    if not path.exists():
        if config is not None:
            raise GateError(f"Configuration does not exist: {path}")
        return Policy()
    try:
        with path.open("rb") as file:
            data = tomllib.load(file)
        section = data.get("policy", {})
        if not isinstance(section, dict):
            raise ValueError("[policy] must be a table")
        rr, rj = section.get("require_rule", True), section.get("require_reason", True)
        if not isinstance(rr, bool) or not isinstance(rj, bool):
            raise ValueError("require_rule and require_reason must be booleans")
        protected = section.get("protected", {})
        if not isinstance(protected, dict):
            raise ValueError("[policy.protected] must be a table")
        parsed: dict[str, frozenset[str]] = {}
        for kind, rules in protected.items():
            if kind not in {"ruff", "bandit", "semgrep"}:
                raise ValueError(f"Unknown protected-rule tool: {kind}")
            if not isinstance(rules, list) or not all(isinstance(x, str) and x.strip() for x in rules):
                raise ValueError(f"Protected rules for {kind} must be a list of strings")
            parsed[kind] = frozenset(x.strip().upper() if kind != "semgrep" else x.strip() for x in rules)
        return Policy(rr, rj, parsed)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        raise GateError(f"Invalid policy {path}: {exc}") from exc


def load_review_policy(root: Path, base: str, config: Path | None = None) -> Policy:
    """Select a policy that the proposed Git change cannot weaken.

    A policy inside the repository must match the policy at the base commit
    byte-for-byte. Policy edits are deliberately a hard error: such changes
    require a separate, explicitly reviewed commit before suppressions can be
    evaluated against them. An explicitly provided policy *outside* the Git
    worktree is treated as caller-controlled (e.g. a trusted CI policy file).
    """
    git_root = _git_root(root.resolve())
    commit = _base_commit(git_root, base)
    path = (config if config is not None else git_root / ".suppressgate.toml").absolute()

    # Use canonical paths for the trust boundary, not Path.absolute(): on
    # Windows, an alias/short path (or a path containing '..') can otherwise
    # make an in-repository config appear to be an external trusted policy.
    # Reject links/junctions in the supplied path rather than allowing a
    # repository-controlled redirect to masquerade as an external config.
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink() or (hasattr(ancestor, "is_junction") and ancestor.is_junction()):
            raise GateError(f"Policy path must not contain symlinks or junctions: {path}")
    try:
        relative = path.resolve().relative_to(git_root.resolve()).as_posix()
    except ValueError:
        # External policies must be supplied explicitly by the CI operator.
        # A pull request cannot change such a file through the checked repo.
        if config is None:
            raise GateError(f"Unexpected external repository policy: {path}")
        return load_policy(git_root, path)

    names = _run_git(git_root, "ls-tree", "-rz", "--name-only", commit, "--", relative)
    in_base = relative.encode("utf-8", errors="surrogateescape") in names.split(b"\0")
    baseline = _run_git(git_root, "show", f"{commit}:{relative}") if in_base else None
    try:
        current = path.read_bytes() if path.exists() else None
    except OSError as exc:
        raise GateError(f"Cannot read policy file {path}: {exc}") from exc
    # Git may store text with LF line endings while a Windows checkout uses
    # CRLF. TOML treats those line endings equivalently, so do not mistake a
    # normal Windows checkout for a policy change. Preserve the missing-file
    # distinction and compare all other bytes strictly.
    def canonical_line_endings(content: bytes | None) -> bytes | None:
        return None if content is None else content.replace(b"\r\n", b"\n")

    if canonical_line_endings(current) != canonical_line_endings(baseline):
        raise GateError(
            f"Policy {relative} differs from base commit {commit[:12]}; "
            "review and merge policy changes separately before checking suppressions"
        )
    return load_policy(git_root, path if config is not None else None)


def _decode_source(raw: bytes, name: str) -> str:
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        return raw.decode(encoding)
    except (SyntaxError, UnicodeError, LookupError) as exc:
        raise GateError(f"Cannot decode {name}: {exc}") from exc


def _normalise_code(code: str) -> str:
    """Ignore formatting, retain token meaning; gracefully handle partial lines."""
    if not code.strip():
        return ""
    tokens: list[str] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(code + "\n").readline):
            if tok.type not in {
                tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE,
                tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER,
            }:
                tokens.append(f"{tok.type}:{tok.string}")
    except (tokenize.TokenError, IndentationError):
        return _CODE.sub("", code.strip())
    return "|".join(tokens)


def _code_anchor(lines: list[str], line_number: int, comment_start: int) -> str:
    before_comment = lines[line_number - 1][:comment_start].strip()
    if before_comment:
        return _normalise_code(before_comment)
    # Standalone directives such as '# nosemgrep: rule' often guard the NEXT line.
    # Only a short lookahead is claimed. We do not try to understand Python scopes.
    for candidate in lines[line_number : line_number + 3]:
        cleaned = candidate.strip()
        if cleaned and not cleaned.startswith("#"):
            return _normalise_code(candidate)
    return "<standalone-unanchored>"


def _parse_payload(kind: str, fragment: str) -> tuple[tuple[str, ...], str]:
    # A consistent optional local convention: '-- human-written justification'.
    # The underlying tools may accept other syntaxes. We document this subset.
    payload, separator, reason = fragment.partition("--")
    payload = payload.strip().lstrip(":").strip()
    raw_rules = re.split(r"[\s,]+", payload) if payload else []
    # Treat annotations without a rule selector as blanket suppressions.
    rules = tuple(sorted(set(x.upper() if kind != "semgrep" else x for x in raw_rules if x)))
    return rules, reason.strip() if separator else ""


def scan_source(raw: bytes, relative_path: str, identity_path: str | None = None) -> list[Suppression]:
    """Use Python's tokenizer so occurrences inside strings aren't counted."""
    source = _decode_source(raw, relative_path)
    lines = source.splitlines()
    result: list[Suppression] = []
    try:
        comment_tokens = (
            token for token in tokenize.generate_tokens(io.StringIO(source).readline)
            if token.type == tokenize.COMMENT
        )
        for token in comment_tokens:
            text = token.string
            # Only actual directive positions: start of the COMMENT token,
            # after '# type: ...', or following an already accepted directive.
            # Do not treat prose like "# Here is an example '# noqa'" as one.
            matches = []
            for match in _DIRECTIVE.finditer(text):
                prefix = text[: match.start()]
                if match.start() == 0 or matches or re.match(r"^#\s*type\s*:", prefix, re.IGNORECASE):
                    matches.append(match)
            for index, match in enumerate(matches):
                end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
                fragment = text[match.end() : end]
                kind = {"noqa": "ruff", "nosec": "bandit", "nosemgrep": "semgrep"}[match.group(1).lower()]
                rules, reason = _parse_payload(kind, fragment)
                line = token.start[0]
                anchor = _code_anchor(lines, line, token.start[1])
                # A rename is explicitly mapped to its old path before comparing.
                canonical_path = (identity_path or relative_path).replace("\\", "/")
                identity = json.dumps([canonical_path, kind, rules, anchor], separators=(",", ":"))
                result.append(
                    Suppression(
                        path=relative_path.replace("\\", "/"),
                        line=line,
                        kind=kind,
                        rules=rules,
                        reason=reason,
                        anchor=anchor,
                        comment=text,
                        fingerprint=hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16],
                    )
                )
    except (tokenize.TokenError, IndentationError, SyntaxError) as exc:
        raise GateError(f"Cannot safely tokenize {relative_path}: {exc}") from exc
    return result


def _run_git(root: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, check=False
        )
    except OSError as exc:
        raise GateError(f"Git unavailable: {exc}") from exc
    if result.returncode:
        details = result.stderr.decode(errors="replace").strip()
        raise GateError(f"Git {' '.join(args[:2])} failed: {details or 'unknown error'}")
    return result.stdout


def _git_root(root: Path) -> Path:
    output = _run_git(root, "rev-parse", "--show-toplevel")
    return Path(output.decode("utf-8", errors="surrogateescape").strip()).resolve()


def _base_commit(root: Path, base: str) -> str:
    if not base or base.startswith("-"):
        raise GateError("--base must be a valid Git ref, not an option")
    raw = _run_git(root, "rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}")
    return raw.decode("ascii").strip()


def _tracked_python(root: Path) -> list[str]:
    out = _run_git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    return sorted({
        name.decode("utf-8", errors="surrogateescape")
        for name in out.split(b"\0") if name and Path(name.decode("utf-8", errors="surrogateescape")).suffix in _SOURCE_SUFFIXES
    })


def _base_python(root: Path, commit: str) -> list[str]:
    out = _run_git(root, "ls-tree", "-rz", "--name-only", commit)
    return sorted({
        name.decode("utf-8", errors="surrogateescape")
        for name in out.split(b"\0") if name and Path(name.decode("utf-8", errors="surrogateescape")).suffix in _SOURCE_SUFFIXES
    })


def _renames(root: Path, commit: str) -> dict[str, str]:
    """Map new paths to old paths using Git's rename detection."""
    raw = _run_git(root, "diff", "--name-status", "-z", "--find-renames", commit, "--")
    fields = [x.decode("utf-8", errors="surrogateescape") for x in raw.split(b"\0") if x]
    result: dict[str, str] = {}
    index = 0
    while index < len(fields):
        status = fields[index]
        index += 1
        if status.startswith(("R", "C")):
            if index + 1 >= len(fields):
                raise GateError("Unexpected Git rename response")
            old, new = fields[index], fields[index + 1]
            index += 2
            result[new] = old
        else:
            index += 1
    return result


def scan_worktree(root: Path) -> list[Suppression]:
    root = root.resolve()
    results: list[Suppression] = []
    for name in _tracked_python(root):
        path = root / name
        if not path.is_file() or path.is_symlink():
            continue
        try:
            results.extend(scan_source(path.read_bytes(), name))
        except OSError as exc:
            raise GateError(f"Cannot read {name}: {exc}") from exc
    return sorted(results, key=lambda x: (x.path, x.line, x.kind))


def scan_directory(root: Path) -> list[Suppression]:
    root = root.resolve()
    if not root.is_dir():
        raise GateError(f"Not a directory: {root}")
    result: list[Suppression] = []
    # `scan` also works without Git. Prune generated/vendor directories before
    # descending, rather than paying to recursively traverse them.
    for folder, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(
            directory for directory in directories
            if directory not in _SKIP_FOLDERS and not (Path(folder) / directory).is_symlink()
        )
        for filename in sorted(filenames):
            path = Path(folder) / filename
            if path.suffix not in _SOURCE_SUFFIXES or not path.is_file() or path.is_symlink():
                continue
            name = path.relative_to(root).as_posix()
            try:
                result.extend(scan_source(path.read_bytes(), name))
            except OSError as exc:
                raise GateError(f"Cannot read {name}: {exc}") from exc
    return sorted(result, key=lambda x: (x.path, x.line, x.kind))


def _compare(base: list[Suppression], current: list[Suppression]) -> list[tuple[str, Suppression]]:
    """Match individual instances, not per-rule suppression counts.

    Match all exact pairs *first*, then pair any remaining instances with
    changed justifications, and finally report genuinely new instances. This
    avoids double-reporting when duplicate suppression instances are reordered.
    """
    old: dict[str, list[Suppression]] = defaultdict(list)
    now: dict[str, list[Suppression]] = defaultdict(list)
    for item in base:
        old[item.fingerprint].append(item)
    for item in current:
        now[item.fingerprint].append(item)

    changes: list[tuple[str, Suppression]] = []
    for fingerprint, new_items in now.items():
        available = old[fingerprint].copy()
        unmatched: list[Suppression] = []
        for item in new_items:
            exact = next((i for i, prior in enumerate(available) if prior.reason == item.reason), None)
            if exact is not None:
                available.pop(exact)
            else:
                unmatched.append(item)
        for item in unmatched:
            if available:
                available.pop(0)
                changes.append(("modified", item))
            else:
                changes.append(("new", item))
    return changes


def _policy_checks(item: Suppression, policy: Policy) -> tuple[str, ...]:
    flags = ["NEW_SUPPRESSION"]
    if policy.require_rule and not item.rules:
        flags.append("MISSING_RULE_ID")
    if policy.require_reason and not item.reason:
        flags.append("MISSING_JUSTIFICATION")
    protected_rules = policy.protected_rules(item.kind)
    # A blanket suppression can silence any protected rule. Blocking only
    # explicitly named IDs would let `# noqa -- explanation` bypass the
    # protected-rule policy when require_rule is disabled.
    if protected_rules and (not item.rules or any(rule in protected_rules for rule in item.rules)):
        flags.append("PROTECTED_RULE_SUPPRESSED")
    return tuple(flags)


def check_git(root: Path, base: str, policy: Policy) -> tuple[list[Finding], str]:
    git_root = _git_root(root.resolve())
    commit = _base_commit(git_root, base)
    renames = _renames(git_root, commit)
    prior: list[Suppression] = []
    for name in _base_python(git_root, commit):
        raw = _run_git(git_root, "show", f"{commit}:{name}")
        prior.extend(scan_source(raw, name))
    current: list[Suppression] = []
    for name in _tracked_python(git_root):
        path = git_root / name
        if not path.is_file() or path.is_symlink():
            continue
        try:
            current.extend(scan_source(path.read_bytes(), name, renames.get(name)))
        except OSError as exc:
            raise GateError(f"Cannot read {name}: {exc}") from exc
    findings = [Finding(change, item, _policy_checks(item, policy)) for change, item in _compare(prior, current)]
    return sorted(findings, key=lambda f: (f.suppression.path, f.suppression.line)), commit
