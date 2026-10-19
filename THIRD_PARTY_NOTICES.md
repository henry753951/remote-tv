# Attribution

Remote TV includes code from [corvofeng/atv-core](https://github.com/corvofeng/atv-core)
(commit `8a4ada29bb7cad31e0315c3387b277eb9ab8c988`). The upstream workspace manifest
and README declare the MIT license. Original source notices are retained.

The Rust core and Android bridge remain in their original namespaces to keep JNI
and protocol interfaces compatible. The Android application has its own package ID.
Workspace CLI sources are retained with the original Cargo.lock; Android is the
supported release target.

Dependencies retain their own licenses, including dadb (Apache-2.0), AndroidX
(Apache-2.0), Kotlin (Apache-2.0), and the Rust packages recorded in Cargo.lock.
See each upstream distribution for its complete license terms.

Apple, iPhone, iPad, Apple TV and AirPlay are trademarks of Apple Inc. This project
is independent and is not affiliated with or endorsed by Apple Inc.

License texts and dependency notices are also bundled in the APK asset
`third-party-licenses.txt`.
