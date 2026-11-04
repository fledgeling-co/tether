# Contributing

Open an issue describing the affected platform and a reproducible flow, or submit a focused pull request with the relevant checks. Report security problems through [private vulnerability reporting](https://github.com/fledgeling-co/tether/security/advisories/new), rather than a public issue. Remove pairing codes, private identity material and application payloads from reports.

Start with [the build guide](docs/INSTALLING.md) and [native UI conventions](docs/NATIVE_UI.md). Run `scripts/gate.sh` for Rust changes, Swift tests for Apple changes, the Windows build and package checks for .NET changes, and the Android module tests for Kotlin/JNI changes. CI records compilation and unit results separately from actual device checks.

Keep changes scoped. Preserve app identities, service allowlists, generation checks and explicit route selection. A failed connection must not reset trust. UI components should inherit the embedding app's theme, retain visible field labels and explain the difference between leaving a host and forgetting it locally.

Include a regression case when fixing a behavioral defect. Native screenshots should come from the affected app and identify fixture data. A successful build does not establish physical-device, internet or accessibility acceptance. Contributions use the repository's MIT license.
