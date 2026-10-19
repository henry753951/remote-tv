# Releasing Remote TV

1. Update the Android version name and version code. Run all CI checks.
2. Build the release APK using the README instructions. The repository contains
   no release keystore; retain the same signing identity for future updates.
3. Sign with Android SDK `apksigner`. Read passwords from protected files or
   environment variables, never command-line literals or committed configuration.
   Verify the signature with `apksigner verify --verbose`.
4. Inspect the APK, commit and source archive for credentials, private paths and
   runtime data. Compute SHA-256 checksums for release assets.
5. Tag the exact source commit, create a GitHub release, and attach the signed APK,
   complete source archive and `SHA256SUMS`. Retain license notices and the Cargo
   lockfile. Exclude Git metadata and build outputs.

CI artifacts are unsigned build outputs for development. The signed APK attached
to a GitHub release is the installable distribution. Self-built APKs use your own
signing identity and may not update an APK signed by another key.
