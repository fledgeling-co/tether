#!/usr/bin/env python3
"""Refuse local contributor paths in distributable native binaries and archives."""
import argparse
import json
from pathlib import Path
import re
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("paths", nargs="+", type=Path)
args = parser.parse_args()
pattern = re.compile(rb"/(?:Users/[^/\s\x00]+|Volumes/LLMs)/|[A-Za-z]:[\\/]+Users[\\/]", re.IGNORECASE)
records = []
for path in args.paths:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            if archive.testzip() is not None:
                parser.error("archive CRC failed: " + str(path))
            entries = [(name, len(pattern.findall(archive.read(name)))) for name in archive.namelist() if not name.endswith("/")]
    else:
        entries = [(path.name, len(pattern.findall(path.read_bytes())))]
    records.append({"file": str(path), "entriesChecked": len(entries), "violations": [{"entry": name, "count": count} for name, count in entries if count]})
print(json.dumps({"passed": not any(row["violations"] for row in records), "files": records}))
raise SystemExit(any(row["violations"] for row in records))
