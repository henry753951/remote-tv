> [!IMPORTANT]
> This standalone receiver has moved into [AirPlay & Remote Receiver](https://github.com/henry753951/airplay-remote-receiver). The combined app provides AirPlay and native Apple TV Remote reception with shared TV settings. This repository is archived for source history; use the combined project for new installations.

<img src="docs/assets/icon.svg" width="88" alt="Remote TV icon" />

# Remote TV

Use the Apple TV Remote already built into your iPhone to control an Android TV.
A small background receiver handles pairing, encrypted control and directional
input; no extra iPhone app or always-on computer is required.

[![Build](https://github.com/henry753951/remote-tv/actions/workflows/build.yml/badge.svg)](https://github.com/henry753951/remote-tv/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**[Download](https://github.com/henry753951/remote-tv/releases/latest)** ·
**[繁體中文](docs/README.zh-TW.md)** · [Contributing](CONTRIBUTING.md)

## Features

- Discovery in iPhone/iPad Control Center's Apple TV Remote.
- On-screen random pairing PIN and stored controller verification keys.
- Direction, select, back, home, playback, volume and power key mapping.
- Directional buttons respond on press; swipes dispatch before finger lift.
- A persistent local input worker avoids starting a Java process for each key.
- Foreground background service and startup after boot.
- Minimal English and Traditional Chinese pairing UI and a TV launcher icon.

## Requirements

Android 8.0 / API 26 or newer, `armeabi-v7a`, and a shared local network permitting
multicast discovery. Firmware must expose legacy TCP ADB at `127.0.0.1:5555`, and
the TV must authorize this app's independent debugging key.

USB debugging alone exposes TCP ADB on some TVs; others need a separate network
debugging option. Android's newer Wireless Debugging pairing-code protocol is
not implemented. If the firmware does not provide the required loopback ADB
service, this release cannot inject directional keys. Root is not required.

## Install and pair

1. Enable the required debugging service in the TV's developer settings.
2. Install the signed **Remote TV** APK from **Releases**, then open it.
3. Allow the TV's debugging authorization prompt. Select **Always allow** only
   when you recognize the connection being configured.
4. On iPhone/iPad, open **Control Center → Apple TV Remote → Remote TV**.
5. Enter the pairing code shown on the TV. The pairing screen closes after
   verification; the receiver continues running in the background.

**Prefer arrows to a touchpad?** Enable **Settings → Accessibility → Apple TV Remote →
Directional Buttons** on your iPhone, then return to the remote.
[Apple's guide](https://support.apple.com/guide/iphone/iph2ec3a3aa6/ios).

| Phone action | Android key |
| --- | --- |
| Arrows / swipe | D-pad up, down, left, right |
| Select | D-pad center |
| Back | Back |
| TV / Home | Home |
| Play/pause | Media play/pause |
| Volume / mute | Volume up/down/mute |
| Power | Power toggle |

Key availability depends on iOS and the receiving app. Long-press repeat, text
keyboard, Siri audio input and every vendor's standby behavior are not guaranteed.
Remote TV controls the TV; it does not receive AirPlay video. For mirroring,
install [AirPlay TV](https://github.com/henry753951/airplay-tv) separately.

## Build and test

| Tool | Version |
| --- | --- |
| JDK | 17 |
| Rust | 1.98.0 |
| Gradle / Android Gradle Plugin | 8.9 / 8.5.2 |
| Android SDK / Build Tools | 34 / 34.0.0 |
| Android NDK | 27.0.12077973 |

Install the listed SDK components and Rust target `armv7-linux-androideabi`.
Set `ANDROID_HOME`; `ANDROID_NDK_HOME` may override the pinned NDK location.

```sh
git clone https://github.com/henry753951/remote-tv.git
cd remote-tv
# Optional toolchain provisioning with mise: mise trust && mise install
cargo test --locked -p atv-core
./scripts/build-android.sh
```

The script builds the ARMv7 Rust JNI library, packages the Android app and runs
release lint. Output: `android-tv/app/build/outputs/apk/release/app-release-unsigned.apk`.
Sign it with your own release key before installation. See [release instructions](docs/RELEASING.md).
CI artifacts are unsigned and are not the signed release download.

## Security and compatibility

Control messages require successful pair verification. Pairing attempts are
rate-limited, signing seeds are generated on-device, and the Android build disables
the inherited HTTP debug controller. ADB input is restricted to known key codes.
See [SECURITY.md](SECURITY.md). Do not expose ADB or receiver ports to the internet.

The input worker uses Android's non-public InputManager API through the authorized
shell connection. Firmware updates can affect compatibility. No fixed end-to-end
latency is promised; network, app rendering and panel refresh also affect response.

## License and credits

MIT; see [LICENSE](LICENSE) and [third-party notices](THIRD_PARTY_NOTICES.md).
Based on [corvofeng/atv-core](https://github.com/corvofeng/atv-core). Android is the
supported distribution target. Independent project; not affiliated with or
endorsed by Apple Inc.
