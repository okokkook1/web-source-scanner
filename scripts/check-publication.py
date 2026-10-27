"""Fail if a directory contains customer identifiers, secrets, PII or artifacts.

Usage:
    python scripts/check-publication.py [path ...]   (default: current directory)

Exit code 0 = clean, 1 = at least one error. Matched secret values are never
printed; only the location and a masked hint are shown.
"""
import argparse
import pathlib
import re
import sys

SKIP_DIRS = {
    ".git",
    "target",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".idea",
    ".vscode",
}
# This checker contains the forbidden patterns themselves.
SKIP_FILES = {"scripts/check-publication.py"}

BINARY_EXT = {
    ".exe", ".dll", ".pdb", ".ilk", ".lib", ".obj", ".bin", ".msi", ".iso",
    ".zip", ".7z", ".rar", ".tar", ".gz", ".db", ".sqlite", ".sqlite3", ".log",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".pdf", ".docx",
    ".xlsx", ".pptx", ".mp3", ".mp4", ".mov",
}

# Customer / engagement identifiers that must not be published.
CLIENT_LITERALS = [
    "抽管系統",
    "抽水站",
    "抽水站管理",
    "pumpstation",
    "PumpStation",
    "Core.Website",
    "Heo.Extend",
    "OverhaulList",
    "E:\\工具",
    "E:/工具",
]

IDENTITY_LITERALS = ["okokk", "C:\\Users\\", "C:/Users/"]

SECRET_PATTERNS = [
    r"""(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*["']([^"']{6,})["']""",
    r"""(?i)\b(accountkey|sharedaccesssignature)\s*=\s*[A-Za-z0-9+/=]{10,}""",
    r"""AKIA[0-9A-Z]{16}""",
    r"""(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}""",
    r"""(?i)(?:data source|server)\s*=[^;\n]{1,80};\s*(?:user id|uid)\s*=[^;\n]{1,80};\s*(?:password|pwd)\s*=""",
]

# Obviously fake values used by the redaction tests.
FAKE_VALUES = {
    "privatessecret321",
    "top secret suffix",
    "changeme",
    "example",
    "dummy",
    "test",
    "secret",
    "password",
    "examplesecret123",
    "examplesecret321",
    "examplesecret456",
    "examplesecret789",
    "exampletokenabcdef1234567890",
    "[已遮蔽]",
    "[私密金鑰已遮蔽]",
    "[連線字串已遮蔽]",
}

TAIWAN_ID = re.compile(r"\b[A-Z][12]\d{8}\b")
MOBILE = re.compile(r"\b09\d{2}-?\d{3}-?\d{3}\b")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"
)
USER_PATH = re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s\"']+")

errors: list[tuple[str, str, str]] = []
warnings: list[tuple[str, str, str]] = []


def add_error(where: str, kind: str, detail: str) -> None:
    errors.append((where, kind, detail))


def add_warning(where: str, kind: str, detail: str) -> None:
    warnings.append((where, kind, detail))


def fake_present(lowered: str) -> bool:
    return any(
        marker in lowered
        for marker in (
            "privatessecret321",
            "top secret suffix",
            "changeme",
            "dummy-secret",
            "exampletokenabcdef1234567890",
            "example.com",
            "example.org",
        )
    )


def scan_file(root: pathlib.Path, path: pathlib.Path) -> None:
    rel = path.relative_to(root).as_posix()
    if rel in SKIP_FILES or path.name == "check-publication.py":
        return
    size = path.stat().st_size
    suffix = path.suffix.lower()
    if suffix in BINARY_EXT:
        add_error(rel, "artifact", f"binary/package file ({size} bytes) must not be published")
        return
    if size > 1_000_000:
        add_warning(rel, "size", f"file is larger than 1 MB ({size} bytes)")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        add_error(rel, "io", f"cannot read: {exc}")
        return
    if b"\x00" in raw[:8192]:
        add_error(rel, "artifact", "binary content detected")
        return
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    for index, line in enumerate(lines):
        number = index + 1
        where = f"{rel}:{number}"
        lowered = line.lower()
        if "BEGIN" in line and "PRIVATE KEY" in line:
            body = "\n".join(lines[index : index + 5])
            if re.search(r"[A-Za-z0-9+/=]{40,}", body):
                add_error(where, "secret", "private key block")
        for literal in CLIENT_LITERALS:
            if literal.lower() in lowered:
                add_error(where, "client", "customer/system identifier")
                break
        for literal in IDENTITY_LITERALS:
            if literal.lower() in lowered and "github.com/" not in lowered:
                add_error(where, "identity", "local user name or absolute user path")
                break
        if USER_PATH.search(line):
            add_error(where, "identity", "absolute Windows user path")
        if fake_present(lowered):
            continue
        for pattern in SECRET_PATTERNS:
            match = re.search(pattern, line)
            if not match:
                continue
            value = (match.group(2) if match.lastindex and match.lastindex >= 2 else "")
            cleaned = value.strip()
            if cleaned and (
                cleaned.lower() in FAKE_VALUES
                or cleaned.startswith("${")
                or cleaned.startswith("{{")
                or cleaned.startswith("<")
            ):
                continue
            add_error(where, "secret", "looks like a real credential")
            break
        if TAIWAN_ID.search(line):
            add_error(where, "pii", "Taiwan national ID pattern")
        if MOBILE.search(line):
            add_error(where, "pii", "mobile phone pattern")
        for email in EMAIL.findall(line):
            domain = email.rsplit("@", 1)[-1].lower()
            if domain.endswith(("example.com", "example.org", "example.net", "test", "localhost")):
                continue
            add_error(where, "pii", "email address")
            break
        if PRIVATE_IP.search(line):
            add_error(where, "network", "private IP address")


def scan(root: pathlib.Path) -> None:
    if not root.is_dir():
        add_error(str(root), "io", "not a directory")
        return
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_file():
            scan_file(root, path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", default=["."])
    parser.add_argument(
        "--summary",
        action="store_true",
        help="print per-category and per-folder counts instead of every match",
    )
    args = parser.parse_args()
    for value in args.paths:
        scan(pathlib.Path(value).resolve())

    if args.summary:
        import collections

        by_kind = collections.Counter(kind for _, kind, _ in errors)
        by_folder = collections.Counter(where.split("/", 1)[0] for where, _, _ in errors)
        for kind, count in by_kind.most_common():
            print(f"{count:6}  {kind}")
        print()
        for folder, count in by_folder.most_common(20):
            print(f"{count:6}  {folder}")
        print()
    else:
        for where, kind, detail in errors:
            print(f"ERROR  {kind:9} {where}  {detail}")
    for where, kind, detail in warnings:
        print(f"WARN   {kind:9} {where}  {detail}")
    print(f"\n{len(errors)} error(s), {len(warnings)} warning(s)")
    if errors:
        print("This directory is NOT safe to publish. Remove or rewrite the listed items.")
        return 1
    print("No customer identifiers, credentials, PII or binary artifacts were found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
