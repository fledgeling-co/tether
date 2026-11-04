#!/usr/bin/env python3
"""Exercise source-publication refusal controls in isolated temporary trees."""
import contextlib
import copy
import importlib.util
import json
import os
import subprocess
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("tether_source_export", HERE / "export.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
POLICY = json.loads((HERE / "policy.json").read_text())
REPO = HERE.parents[1]


@contextlib.contextmanager
def fixture():
    with tempfile.TemporaryDirectory(prefix="tether-export-control-") as temp:
        base = Path(temp).resolve(); root = base / "source"; root.mkdir()
        for name in POLICY["required"]:
            path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# Tether\n" if path.suffix == ".md" else "synthetic source\n")
        for name in POLICY["binarySources"]:
            path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((REPO / name).read_bytes())
        yield root, base / "public"


def issue(result, kind):
    return any(row["type"] == kind for row in result["issues"])


def refuses(action):
    try:
        action()
    except ValueError:
        return True
    return False


def run():
    passed = []
    with fixture() as (root, out):
        (root / "scripts/public-release/export.py").chmod(0o755)
        result = MODULE.audit(root, POLICY)
        assert result["passed"]
        MODULE.export(root, out, POLICY, result)
        assert MODULE.audit(out, POLICY, strict_tree=True)["passed"]
        assert (out / "scripts/public-release/export.py").stat().st_mode & 0o100
        assert not (out / ".git").exists()
        passed.append("exact source snapshot and executable bits without Git history")
    with fixture() as (root, out):
        for name in (".status/project.json", "planning/evidence/private.json", ".claude/settings.json", "packages/android/local.properties"):
            path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("private fixture\n")
        result = MODULE.audit(root, POLICY); assert result["passed"]
        MODULE.export(root, out, POLICY, result)
        assert not (out / ".status").exists() and not (out / "planning").exists()
        assert not (out / "packages/android/local.properties").exists()
        passed.append("owner reports and local configuration stay outside snapshot")
    with fixture() as (root, _):
        p = root / "crates/core/leak.txt"; p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("ghp_" + "x" * 40)
        assert issue(MODULE.audit(root, POLICY), "provider-token")
        passed.append("credential-shaped provider token refuses")
    with fixture() as (root, _):
        p = root / "crates/core/leak.txt"; p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("-----BEGIN " + "PRIVATE KEY-----")
        assert issue(MODULE.audit(root, POLICY), "private-key")
        passed.append("private-key envelope refuses")
    with fixture() as (root, _):
        p = root / "crates/core/path.txt"; p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("/" + "Users" + "/fixture/private")
        assert issue(MODULE.audit(root, POLICY), "personal-absolute-path")
        passed.append("personal absolute path refuses")
    with fixture() as (root, _):
        p = root / "crates/core/external.link"; p.parent.mkdir(parents=True, exist_ok=True)
        external = root.parent / "outside"; external.write_text("outside source")
        p.symlink_to(external)
        assert issue(MODULE.audit(root, POLICY), "unsafe-or-unselected-symlink")
        passed.append("external symlink refuses")
    with fixture() as (root, out):
        p = root / "crates/core/license.link"; p.parent.mkdir(parents=True, exist_ok=True)
        p.symlink_to("../../LICENSE")
        result = MODULE.audit(root, POLICY); assert result["passed"]
        MODULE.export(root, out, POLICY, result)
        assert (out / "crates/core/license.link").is_symlink()
        passed.append("relative symlink to selected source remains portable")
    with fixture() as (root, out):
        out.mkdir(); marker = out / "keep"; marker.write_text("owned elsewhere")
        assert refuses(lambda: MODULE.export(root, out, POLICY, MODULE.audit(root, POLICY)))
        assert marker.read_text() == "owned elsewhere"
        passed.append("existing destination refuses without overwriting")
    with fixture() as (root, _):
        (root / "LICENSE").unlink()
        assert issue(MODULE.audit(root, POLICY), "required-source-missing")
        passed.append("missing license refuses")
    with fixture() as (root, _):
        p = root / "crates/core/opaque.dat"; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b"\xff\x00")
        assert issue(MODULE.audit(root, POLICY), "unapproved-binary")
        passed.append("unapproved binary refuses")
    with fixture() as (root, _):
        p = root / "docs/assets/opaque.png"; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b"\xff\x00")
        assert issue(MODULE.audit(root, POLICY), "unapproved-binary")
        passed.append("renamed binary documentation asset refuses")
    with fixture() as (root, _):
        (root / "README.md").write_text("[Missing](missing.md)\n")
        assert issue(MODULE.audit(root, POLICY), "document-link-target-not-exported")
        passed.append("broken public documentation link refuses")
    with fixture() as (root, out):
        result = MODULE.audit(root, POLICY); assert result["passed"]
        (root / "LICENSE").write_text("modified after audit\n")
        assert refuses(lambda: MODULE.export(root, out, POLICY, result)) and not out.exists()
        passed.append("source drift before copy refuses")
    with fixture() as (root, _):
        value = "wss:" + "//user:secret@relay.example"
        expected = root / "packages/TetherKit/Tests/TetherUITests/InvitationTests.swift"
        expected.parent.mkdir(parents=True, exist_ok=True); expected.write_text(value)
        result = MODULE.audit(root, POLICY); assert result["passed"] and len(result["fixtureExemptions"]) == 1
        wrong = root / "crates/core/wrong.txt"; wrong.parent.mkdir(parents=True, exist_ok=True); wrong.write_text(value)
        assert issue(MODULE.audit(root, POLICY), "credential-url")
        passed.append("fixture exemption binds exact path and value digest")
    with fixture() as (root, out):
        # Git mutations are confined to this disposable fixture, never the source repository.
        assert root.is_relative_to(Path(tempfile.gettempdir()).resolve()) and root != REPO.resolve()
        git_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        git_env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        def git(*args):
            subprocess.run(["git", "-c", "core.hooksPath=" + os.devnull,
                            "-c", "commit.gpgsign=false", "-c", "user.name=Tether export control",
                            "-c", "user.email=export-control@example.invalid", *args],
                           cwd=root, env=git_env, check=True, capture_output=True)
        report = root / "planning/owner-report.txt"; report.parent.mkdir()
        report.write_text("/" + "Users" + "/fixture/private")
        git("init", "--quiet", "--initial-branch=main")
        git("add", "."); git("commit", "--quiet", "-m", "Synthetic owner report")
        git("rm", "--quiet", "planning/owner-report.txt")
        git("commit", "--quiet", "-m", "Remove owner report")
        internal = MODULE.audit(root, POLICY, history=True)
        assert internal["passed"] and len(internal["historyAudit"]["issues"]) == 1
        public = MODULE.audit(root, POLICY, history=True, strict_tree=True)
        assert not public["passed"] and public["historyAudit"]["issues"][0]["type"] == "personal-absolute-path"
        passed.append("public validation refuses removed personal paths in Git history")
        MODULE.export(root, out, POLICY, internal)
        assert MODULE.audit(out, POLICY, strict_tree=True)["passed"]
        assert not (out / ".git").exists() and not (out / "planning").exists()
        passed.append("internal export keeps excluded owner-report history out of fresh snapshot")
    assert refuses(lambda: MODULE.relative("../outside")) and refuses(lambda: MODULE.relative("C:" + "\\outside"))
    passed.append("policy path traversal refuses")
    print(json.dumps({"passed": len(passed), "controls": passed}, indent=2))


if __name__ == "__main__":
    run()
