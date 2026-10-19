# Remote TV

使用 iPhone 內建「Apple TV 遙控器」操控 Android 電視。
電視上的背景服務處理配對、加密連線與按鍵派發，不需要另裝 iPhone App 或讓電腦常開。

[下載 APK](https://github.com/henry753951/remote-tv/releases/latest) · [English](../README.md)

## 安裝與配對

1. 電視需 Android 8.0／API 26 以上、ARM 32 位元 `armeabi-v7a`，
   並支援 `127.0.0.1:5555` 的本機 TCP ADB。
2. 在開發人員選項開啟需要的偵錯服務，安裝並開啟 Remote TV。
3. 電視顯示偵錯授權時，確認是正在設定的連線，再允許；可勾選「永遠允許」。
4. iPhone 與電視連同一區網，開啟「控制中心 → Apple TV 遙控器 → Remote TV」，
   輸入電視畫面的配對碼。

想用上下左右按鈕：iPhone「設定 → 輔助使用 → Apple TV Remote → 方向按鈕」。
配對成功後，電視配對畫面會關閉，接收服務繼續在背景運作。

## 功能與限制

支援方向、確認、返回、首頁、播放、音量與電源按鍵映射。
方向按鈕按下即可送出，觸控滑過門檻就派發方向；本機常駐輸入程序避免每次按鍵重啟 Java。

部分電視開啟 USB 偵錯就提供 TCP ADB；其他機種需另外開啟網路偵錯。
此版本不實作新版「無線偵錯」配對碼協定，韌體未提供本機 5555 服務時無法派發完整方向鍵。
不需要 root；長按連發、文字鍵盤、Siri 音訊及不同廠商待機行為不保證相容。

本 App 提供遙控，不接收投屏；投屏請另用 [AirPlay TV](https://github.com/henry753951/airplay-tv)。

## 自行建置

JDK 17、Rust 1.98.0、Android SDK 34、Build Tools 34.0.0、NDK 27.0.12077973。
安裝 Rust 的 `armv7-linux-androideabi` target，設定 `ANDROID_HOME`：

```sh
cargo test --locked -p atv-core
./scripts/build-android.sh
```

詳見 [英文文件](../README.md)、[安全說明](../SECURITY.md) 與 [發布方式](RELEASING.md)。
MIT 授權，採用 atv-core；完整聲明見 [第三方授權](../THIRD_PARTY_NOTICES.md)。本專案與 Apple Inc. 無關。
