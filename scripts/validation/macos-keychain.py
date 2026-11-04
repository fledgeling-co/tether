#!/usr/bin/env python3
"""Run the native Mac Keychain fixture with an explicitly selected development profile."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--identity", required=True, help="SHA1 of an installed signing identity")
    parser.add_argument("--expected-team", required=True)
    parser.add_argument("--governor", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True, help="New, empty result directory")
    parser.add_argument("--derived-data", type=Path, required=True)
    args = parser.parse_args()
    identity = args.identity.upper()
    if not re.fullmatch(r"[A-F0-9]{40}", identity):
        parser.error("--identity must be a certificate SHA1 fingerprint")
    if not re.fullmatch(r"[A-Z0-9]{10}", args.expected_team):
        parser.error("--expected-team must be an Apple team identifier")
    if not args.governor.is_file() or not os.access(args.governor, os.X_OK):
        parser.error("--governor must select the executable admission wrapper")

    profile = args.profile.resolve(strict=True)
    decoded = subprocess.run(["security", "cms", "-D", "-i", str(profile)],
                             check=True, capture_output=True).stdout
    metadata = plistlib.loads(decoded)
    entitlements = metadata.get("Entitlements", {})
    bundle = "app.fledgeling.tether.validation"
    expected_app = args.expected_team + "." + bundle
    team_ok = (metadata.get("TeamIdentifier") == [args.expected_team]
               and entitlements.get("com.apple.developer.team-identifier") == args.expected_team)
    if not team_ok or entitlements.get("com.apple.application-identifier") != expected_app:
        parser.error("profile team or application identifier does not match the requested validation host")
    if metadata.get("Platform") != ["OSX"] or not metadata.get("ProvisionedDevices"):
        parser.error("use a Mac development profile with an explicitly registered validation device")
    if metadata.get("ExpirationDate", datetime.datetime.min) <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
        parser.error("profile has expired")
    certificates = {hashlib.sha1(item).hexdigest().upper()
                    for item in metadata.get("DeveloperCertificates", [])}
    if identity not in certificates:
        parser.error("selected signing certificate is absent from the profile")
    installed = subprocess.run(["security", "find-identity", "-v", "-p", "codesigning"],
                               check=True, capture_output=True, text=True).stdout
    if not any(identity in line and '"Apple Development:' in line for line in installed.splitlines()):
        parser.error("selected certificate is not an installed Apple Development signing identity")
    groups = entitlements.get("keychain-access-groups", [])
    if expected_app not in groups and args.expected_team + ".*" not in groups:
        parser.error("profile does not authorize the validation host's Keychain group")
    uuid = metadata.get("UUID", "")
    if not re.fullmatch(r"[A-Fa-f0-9-]{36}", uuid):
        parser.error("profile has no valid UUID")

    results = args.results.resolve()
    if results.exists():
        parser.error("--results must not already exist; a prior receipt cannot satisfy this run")
    results.mkdir(mode=0o700, parents=True)
    destination = Path.home() / "Library/Developer/Xcode/UserData/Provisioning Profiles" / (uuid + ".provisionprofile")
    destination.parent.mkdir(parents=True, exist_ok=True)
    data = profile.read_bytes()
    if destination.exists():
        if destination.read_bytes() != data:
            parser.error("a different installed profile already uses this UUID")
    else:
        with destination.open("xb") as output:
            output.write(data)
    repo = Path(__file__).resolve().parents[2]
    project = repo / "packages/TetherKit/ValidationHost"
    evidence = results / "keychain.json"
    command = [str(args.governor.resolve()), "--weight", "1", "--project", "tether",
               "--label", "Mac native Keychain", "--qos", "none", "--",
               "xcodebuild", "-project", str(project / "TetherSDKValidation.xcodeproj"),
               "-scheme", "TetherSDKValidation", "-destination", "platform=macOS,arch=arm64",
               "-parallel-testing-enabled", "NO", "-jobs", "1", "-collect-test-diagnostics", "never",
               "-derivedDataPath", str(args.derived_data.resolve()),
               "-resultBundlePath", str(results / "native.xcresult"),
               "CODE_SIGN_IDENTITY=" + identity,
               "DEVELOPMENT_TEAM=" + args.expected_team,
               "TETHER_VALIDATION_PROFILE=" + uuid,
               "TETHER_VALIDATION_EVIDENCE=" + str(evidence), "test"]
    receipt = {"schema": "tether.mac-keychain-validation/1", "team": args.expected_team,
               "appIdentifier": expected_app, "profileUUID": uuid, "certificateSHA1": identity,
               "command": command, "nativeExecuted": False, "passed": False}
    subprocess.run(["xcodegen", "generate", "--spec", str(project / "project.yml")], check=True)
    with (results / "xcode.log").open("w") as log:
        completed = subprocess.run(command, cwd=repo, stdout=log, stderr=subprocess.STDOUT)
    receipt["exitCode"] = completed.returncode
    if evidence.is_file():
        measured = json.loads(evidence.read_text())
        receipt["nativeExecuted"] = True
        receipt["keychain"] = measured
        receipt["passed"] = (completed.returncode == 0 and measured.get("preflightStatus") == 0
                             and len(measured.get("phases", [])) == 8
                             and measured.get("scopedAccounts") == 6
                             and measured.get("verifiedAbsent") == 6
                             and measured.get("cleanupErrors") == [])
    (results / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"passed": receipt["passed"], "nativeExecuted": receipt["nativeExecuted"],
                      "exitCode": completed.returncode, "receipt": str(results / "receipt.json")}))
    return 0 if receipt["passed"] else (completed.returncode or 1)


if __name__ == "__main__":
    sys.exit(main())
