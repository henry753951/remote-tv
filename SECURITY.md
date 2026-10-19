# Security

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/henry753951/remote-tv/security/advisories/new).
Include the affected version, attack prerequisites, reproduction steps and impact.
Do not post credentials, pairing material or unredacted device logs in public issues.

Use the receiver on a trusted local network. Do not expose its discovery or control
ports to the internet. Network segmentation and guest/client isolation can prevent
discovery. Android firmware and sender updates can change protocol compatibility.

Pairing uses an on-screen random PIN and stored controller public keys. Control
messages require authenticated pair verification. Pairing attempts are rate-limited.
The Android build disables the inherited HTTP debug controller and does not advertise
a second AirPlay receiver. App-private signing and pairing keys are created at runtime.

Local input uses an independently authorized ADB key and a whitelist of key codes.
ADB itself grants powerful shell access: authorize only trusted devices and do not
expose TCP port 5555 beyond a trusted network. The persistent input worker uses a
non-public Android API; firmware upgrades require compatibility testing.
