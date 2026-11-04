#!/usr/bin/env python3
"""Collect dependency notices from a saved `cargo metadata --locked` result."""
import argparse
import hashlib
import json
import re
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("metadata", type=Path)
parser.add_argument("--prior", type=Path, default=Path("THIRD_PARTY_NOTICES.txt"))
parser.add_argument("--output", type=Path, default=Path("THIRD_PARTY_NOTICES.txt"))
args = parser.parse_args()
metadata = json.loads(args.metadata.read_text())
notices = {}
packages = []
missing = []
retained = []
prior_rows = {}
prior_texts = {}
if args.prior.is_file():
    prior = args.prior.read_text()
    for line in prior.splitlines():
        match = re.fullmatch(r"([^|]+) \| ([^|]+) \| notices ([a-f0-9, ]+)", line)
        if match:
            prior_rows[match[1].strip()] = (match[2].strip(), match[3].split(", "))
    parts = re.split(r"=== Notice ([a-f0-9]{16}) ===\n", prior)
    for index in range(1, len(parts), 2):
        prior_texts[parts[index]] = parts[index + 1].strip() + "\n"

for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
    if not package.get("source"):
        continue
    root = Path(package["manifest_path"]).parent
    paths = set()
    if package.get("license_file"):
        paths.add(root / package["license_file"])
    for pattern in ("LICENSE*", "LICENCE*", "COPYING*", "NOTICE*", "license*", "licence*", "copyright*", "Copyright*", "AUTHORS"):
        paths.update(root.glob(pattern))
    # ring and bundled C libraries keep required downstream attribution in these directories.
    for folder in ("LICENSES", "licenses", "third-party", "third_party"):
        directory = root / folder
        if directory.is_dir():
            for path in directory.rglob("*"):
                if path.is_file() and any(key in path.name.upper() for key in ("LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT")):
                    paths.add(path)
    override = Path(__file__).resolve().parent.parent / "licenses" / "overrides" / (package["name"] + "-" + package["version"] + ".txt")
    if override.is_file():
        paths.add(override)
    ids = []
    for path in sorted(paths):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        if b"\x00" in raw:
            continue
        value = "\n".join(line.rstrip() for line in raw.decode("utf-8", errors="replace").splitlines()).strip() + "\n"
        key = hashlib.sha256(value.encode()).hexdigest()[:16]
        notices[key] = value
        ids.append(key)
    if not ids:
        name = package["name"] + " " + package["version"]
        previous = prior_rows.get(name)
        if previous and previous[0] == package.get("license") and all(key in prior_texts for key in previous[1]):
            for old_key in previous[1]:
                value = prior_texts[old_key]
                key = hashlib.sha256(value.encode()).hexdigest()[:16]
                notices[key] = value
                ids.append(key)
            retained.append(name)
        else:
            missing.append(name)
    packages.append(f'{package["name"]} {package["version"]} | {package.get("license") or "license in packaged source"} | notices {", ".join(sorted(set(ids)))}')
if missing:
    raise SystemExit("No packaged license text for: " + ", ".join(missing))
text = "Tether third-party dependency notices\nGenerated from Cargo.lock and packaged dependency source.\n\n"
text += "\n".join(packages) + "\n\n"
for key, value in sorted(notices.items()):
    text += f"=== Notice {key} ===\n{value}\n"
args.output.write_text(text.rstrip() + "\n")
print(f"{len(packages)} dependencies, {len(notices)} distinct notices: {args.output}")
if retained:
    print("Retained exact-version prior notices absent from packaged source: " + ", ".join(retained))
