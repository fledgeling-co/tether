#!/usr/bin/env python3
"""Audit or export a portable, source-only Tether snapshot without local Git history."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.parse

POLICY = Path(__file__).with_name("policy.json")
PATTERNS = {
    "private-key": rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "provider-token": rb"\b(?:sk_live_|ghp_|github_pat_|xox[baprs]-)[A-Za-z0-9_-]{12,}",
    "aws-access-id": rb"\bAKIA[A-Z0-9]{16}\b",
    "credential-url": rb"(?:https?|wss?)://[^/\s:@\"'<>]+:[^/\s@\"'<>]+@[^/\s\"'<>()\\]+(?:/[^\s\"'<>()\\]*)?",
    "personal-absolute-path": rb"/(?:Users/[^/\s\"'`]+|Volumes/LLMs)/",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def relative(path: str) -> str:
    p = PurePosixPath(path)
    if "\\" in path or ":" in path or p.is_absolute() or not p.parts or any(part in ("..", ".") for part in p.parts):
        raise ValueError("policy contains a non-relative path")
    return str(p)


def excluded(name: str, policy: dict) -> bool:
    parts = PurePosixPath(name).parts
    return (any(part in policy["excludeDirectoryNames"] for part in parts[:-1])
            or any(part.endswith(tuple(policy["excludeDirectorySuffixes"])) for part in parts[:-1])
            or name.startswith(tuple(policy["excludePathPrefixes"]))
            or parts[-1] in policy["excludeFileNames"]
            or (parts[-1].startswith(".env") and parts[-1] != ".env.example")
            or name.endswith(tuple(policy["excludeSuffixes"])))


def selected(root: Path, policy: dict) -> list[str]:
    paths = set(policy["files"] + policy["documentation"] + policy["extraFiles"] + list(policy["binarySources"]))
    for prefix in policy["directories"]:
        directory = root / relative(prefix)
        if directory.is_symlink():
            raise ValueError("allowed source directory is a symlink: " + prefix)
        if not directory.exists():
            continue
        for here, dirs, files in os.walk(directory, followlinks=False):
            for entry in dirs:
                target = Path(here) / entry
                if target.is_symlink():
                    raise ValueError("directory symlink is not exportable: " + str(target.relative_to(root)))
            dirs[:] = sorted(d for d in dirs if d not in policy["excludeDirectoryNames"]
                             and not d.endswith(tuple(policy["excludeDirectorySuffixes"])))
            for file in sorted(files):
                name = (Path(here) / file).relative_to(root).as_posix()
                if not excluded(name, policy):
                    paths.add(name)
    return sorted(name for name in paths if not excluded(name, policy) and (root / name).exists())


def inspect_bytes(name: str, raw: bytes, policy: dict, *, history: bool = False) -> tuple[list[dict], list[dict]]:
    issues, fixtures = [], []
    exemptions = {(item["path"], item["sha256"]) for item in policy["credentialFixtureExemptions"]}
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        image = (name.startswith("docs/assets/") and
                 ((Path(name).suffix.lower() == ".png" and raw.startswith(b"\x89PNG\r\n\x1a\n"))
                  or (Path(name).suffix.lower() in (".jpg", ".jpeg") and raw.startswith(b"\xff\xd8\xff"))
                  or (Path(name).suffix.lower() == ".webp" and raw.startswith(b"RIFF") and raw[8:12] == b"WEBP")))
        if not history and policy["binarySources"].get(name) != digest(raw) and not image:
            issues.append({"path": name, "type": "unapproved-binary", "sha256": digest(raw)})
        return issues, fixtures
    for kind, pattern in PATTERNS.items():
        for match in re.finditer(pattern, raw):
            result = {"path": name, "type": kind, "sha256": digest(raw), "line": raw[:match.start()].count(b"\n") + 1}
            if kind == "credential-url" and (name, digest(match.group())) in exemptions:
                fixtures.append(result)
            else:
                issues.append(result)
    return issues, fixtures


def audit_history(root: Path, policy: dict, selected_names: set[str]) -> dict:
    listing = subprocess.run(["git", "rev-list", "--objects", "--all"], cwd=root, check=True,
                             capture_output=True, text=True).stdout.splitlines()
    objects = {}
    for line in listing:
        oid, _, name = line.partition(" ")
        objects.setdefault(oid, name)
    issues, fixtures = [], []
    text_count = binary_count = 0
    proc = subprocess.Popen(["git", "cat-file", "--batch"], cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        assert proc.stdin is not None and proc.stdout is not None
        for oid, name in objects.items():
            proc.stdin.write((oid + "\n").encode()); proc.stdin.flush()
            header = proc.stdout.readline().split()
            if len(header) != 3:
                raise ValueError("could not read Git object metadata")
            size = int(header[2]); raw = proc.stdout.read(size)
            if len(raw) != size or proc.stdout.read(1) != b"\n":
                raise ValueError("could not read complete Git object")
            if header[1] != b"blob":
                continue
            try:
                raw.decode("utf-8"); text_count += 1
            except UnicodeDecodeError:
                binary_count += 1
            found, accepted = inspect_bytes(name, raw, policy, history=True)
            # Personal paths in excluded historical owner reports do not enter the new snapshot.
            for row in found:
                row["object"] = oid
                row["excludedFromSnapshot"] = name not in selected_names
            for row in accepted:
                row["object"] = oid
            issues.extend(found); fixtures.extend(accepted)
        proc.stdin.close()
        if proc.wait() != 0:
            raise ValueError("Git object audit failed")
    finally:
        if proc.poll() is None:
            proc.kill(); proc.wait()
    return {"textBlobs": text_count, "binaryBlobs": binary_count, "issues": issues, "fixtureExemptions": fixtures}


def audit(root: Path, policy: dict, *, history: bool = False, strict_tree: bool = False) -> dict:
    names = selected(root, policy); selected_names = set(names)
    issues, fixtures, records = [], [], []
    for required in policy["required"]:
        if required not in selected_names:
            issues.append({"path": required, "type": "required-source-missing"})
    for name in names:
        path = root / name
        if path.is_symlink():
            target = Path(os.readlink(path))
            resolved = path.resolve()
            if target.is_absolute() or not resolved.is_relative_to(root) or not resolved.is_file() or resolved.relative_to(root).as_posix() not in selected_names:
                issues.append({"path": name, "type": "unsafe-or-unselected-symlink"}); continue
            raw = os.readlink(path).encode()
            records.append({"path": name, "kind": "symlink", "target": os.readlink(path), "sha256": digest(raw)})
            continue
        raw = path.read_bytes()
        if len(raw) > policy["maximumFileBytes"]:
            issues.append({"path": name, "type": "source-file-too-large", "bytes": len(raw)})
        found, accepted = inspect_bytes(name, raw, policy)
        issues.extend(found); fixtures.extend(accepted)
        records.append({"path": name, "kind": "file", "bytes": len(raw), "sha256": digest(raw),
                        "executable": bool(path.stat().st_mode & stat.S_IXUSR)})
        if path.suffix == ".md":
            for link in re.findall(r"\[[^\]]*\]\(([^)]+)\)", raw.decode("utf-8")):
                url = link.split(' "', 1)[0].strip("<>")
                if not url or url.startswith("#") or urllib.parse.urlsplit(url).scheme:
                    continue
                target = urllib.parse.unquote(url.split("#", 1)[0])
                resolved = (path.parent / target).resolve()
                if target.startswith("/") or not resolved.is_relative_to(root):
                    issues.append({"path": name, "type": "nonportable-document-link"}); continue
                rel = resolved.relative_to(root).as_posix()
                if rel not in selected_names and not any(n.startswith(rel.rstrip("/") + "/") for n in names):
                    issues.append({"path": name, "type": "document-link-target-not-exported", "target": rel})
    if strict_tree:
        if (root / ".git").exists():
            tracked = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True).stdout
            strict_names = [name for name in tracked.decode().split("\0") if name]
        else:
            strict_names = []
            for here, dirs, files in os.walk(root, followlinks=False):
                dirs[:] = sorted(d for d in dirs if d not in policy["excludeDirectoryNames"])
                strict_names.extend((Path(here) / file).relative_to(root).as_posix() for file in files)
        for name in strict_names:
            if name not in selected_names:
                issues.append({"path": name, "type": "unexpected-file-in-public-tree"})
    result = {"schema": "tether.public-source-audit/1", "files": records, "fileCount": len(records),
              "totalBytes": sum(row.get("bytes", 0) for row in records), "issues": issues,
              "fixtureExemptions": fixtures, "historyIncludedInSnapshot": False}
    if history:
        result["historyAudit"] = audit_history(root, policy, selected_names)
    history_issues = result.get("historyAudit", {}).get("issues", [])
    # Public repositories must have clean history, including files removed from the current tree.
    # Only an internal fresh-snapshot audit may set aside personal paths in excluded old files.
    exceptions = [row for row in history_issues if not strict_tree
                  and row["type"] == "personal-absolute-path" and row.get("excludedFromSnapshot")]
    result["historyExceptions"] = exceptions
    result["historyBlockingIssues"] = [row for row in history_issues if row not in exceptions]
    result["passed"] = not issues and not result["historyBlockingIssues"]
    return result


def export(root: Path, destination: Path, policy: dict, result: dict) -> None:
    if destination.exists() or destination.is_symlink():
        raise ValueError("destination already exists; choose a new empty snapshot path")
    if destination.is_relative_to(root):
        raise ValueError("destination must be outside the source tree")
    if not result["passed"]:
        raise ValueError("source audit did not pass; no export was created")
    stage = Path(tempfile.mkdtemp(prefix=".tether-public-", dir=destination.parent))
    try:
        for record in result["files"]:
            source = root / record["path"]; target = stage / record["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            if record["kind"] == "symlink":
                if digest(os.readlink(source).encode()) != record["sha256"]:
                    raise ValueError("source symlink changed during export: " + record["path"])
                target.symlink_to(record["target"])
            else:
                raw = source.read_bytes()
                if digest(raw) != record["sha256"]:
                    raise ValueError("source changed during export: " + record["path"])
                target.write_bytes(raw); target.chmod(0o755 if record["executable"] else 0o644)
        verify = audit(stage, policy, strict_tree=True)
        if not verify["passed"] or verify["files"] != result["files"]:
            raise ValueError("exported source does not match the audited input")
        stage.rename(destination)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("audit", "validate", "export"))
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--policy", type=Path, default=POLICY)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--report", type=Path, required=True, help="JSON receipt outside the public tree")
    parser.add_argument("--history", action="store_true", help="Inspect unique Git blobs without exporting history")
    args = parser.parse_args()
    root = args.repo.resolve(strict=True)
    try:
        policy = json.loads(args.policy.read_text())
        for field in ("files", "directories", "documentation", "required", "extraFiles"):
            for name in policy[field]:
                if relative(name) != name:
                    raise ValueError("policy path is not normalized")
        for name in policy["binarySources"]:
            relative(name)
        result = audit(root, policy, history=args.history, strict_tree=args.mode == "validate")
        if args.mode == "export":
            if args.out is None:
                parser.error("export requires --out")
            destination = args.out.resolve()
            if args.report.resolve().is_relative_to(destination):
                parser.error("the receipt must be outside the public snapshot")
            export(root, destination, policy, result)
            result["exportCreated"] = True
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"passed": result["passed"], "files": result["fileCount"],
                          "bytes": result["totalBytes"], "issueCount": len(result["issues"]),
                          "historyIssues": len(result.get("historyAudit", {}).get("issues", [])), "report": str(args.report)}))
        return 0 if result["passed"] else 1
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # Error messages carry paths or fixed policy descriptions; content matches are never printed.
        print(json.dumps({"passed": False, "error": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
