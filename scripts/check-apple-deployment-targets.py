#!/usr/bin/env python3
"""Check generated static archive deployment metadata against the public Swift package floor."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
parser.add_argument("--artifact", type=Path, default=root / "packages/TetherKit/Artifacts/TetherFFI.xcframework")
parser.add_argument("--receipt", type=Path, default=root / "planning/evidence/apple-deployment-targets.json")
args = parser.parse_args()
artifact = args.artifact
info = plistlib.loads((artifact / "Info.plist").read_bytes())
rows = []
violations = []
for library in info["AvailableLibraries"]:
    platform = library["SupportedPlatform"]
    floor = (15, 0) if platform == "macos" else (18, 0)
    path = artifact / library["LibraryIdentifier"] / library["LibraryPath"]
    result = subprocess.run(["xcrun", "otool", "-arch", "all", "-l", str(path)], capture_output=True, text=True, check=True)
    expected_platform = "1" if platform == "macos" else ("7" if library.get("SupportedPlatformVariant") == "simulator" else "2")
    versions = []
    command = None
    for line in result.stdout.splitlines():
        text = line.strip()
        if text.startswith("cmd "):
            command = text.split(maxsplit=1)[1]
        if command == "LC_BUILD_VERSION" and text.startswith("platform ") and text.split()[1] != expected_platform:
            violations.append({"library": library["LibraryIdentifier"], "objectPlatform": text.split()[1], "expectedPlatform": expected_platform})
        match = re.fullmatch(r"(minos|version) (\d+(?:\.\d+){0,2})", text)
        if match and command in ("LC_BUILD_VERSION", "LC_VERSION_MIN_MACOSX", "LC_VERSION_MIN_IPHONEOS"):
            version = tuple(int(x) for x in match[2].split("."))
            version = (version + (0, 0))[:2]
            versions.append(match[2])
            if version > floor:
                violations.append({"library": library["LibraryIdentifier"], "minimum": match[2], "declared": ".".join(map(str, floor))})
    if not versions:
        raise SystemExit("No deployment metadata measured for " + str(path))
    rows.append({"library": library["LibraryIdentifier"], "architectures": library["SupportedArchitectures"],
                 "declaredMinimum": ".".join(map(str, floor)), "objectsMeasured": len(versions),
                 "minimumVersions": sorted(set(versions)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
receipt = {"method": "otool archive load commands; metadata check, not an older-OS runtime test", "libraries": rows, "violations": violations}
output = args.receipt
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(receipt, indent=2) + "\n")
print(json.dumps({"libraries": len(rows), "architectures": sum(len(r["architectures"]) for r in rows), "violations": len(violations), "receipt": str(output)}))
sys.exit(bool(violations))
