//! Android TV controller over ADB: translates Apple TV remote buttons and touch
//! events into ADB commands (`input keyevent`, `input roll`, `input tap`).
//!
//! Uses a persistent `adb shell` session for low-latency response (<10ms).

use std::process::Stdio;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::process::{ChildStdin, Command};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use atv_core::{AtvDelegate, EventKind, TouchPhase};

pub struct AndroidAdbDelegate {
    host: String,
    port: u16,
    mouse_mode: bool,
    shell: Arc<Mutex<Option<ChildStdin>>>,
    screen_size: Arc<Mutex<Option<(f64, f64)>>>,
    pointer: Arc<Mutex<(f64, f64)>>,
}

fn keycode_for_button(name: &str) -> Option<&'static str> {
    match name {
        "up" => Some("KEYCODE_DPAD_UP"),
        "down" => Some("KEYCODE_DPAD_DOWN"),
        "left" => Some("KEYCODE_DPAD_LEFT"),
        "right" => Some("KEYCODE_DPAD_RIGHT"),
        "select" => Some("KEYCODE_DPAD_CENTER"),
        "menu" => Some("KEYCODE_BACK"),
        "home" => Some("KEYCODE_HOME"),
        "play_pause" => Some("KEYCODE_MEDIA_PLAY_PAUSE"),
        "volume_up" => Some("KEYCODE_VOLUME_UP"),
        "volume_down" => Some("KEYCODE_VOLUME_DOWN"),
        "mute" => Some("KEYCODE_VOLUME_MUTE"),
        "power" => Some("KEYCODE_POWER"),
        "siri" => Some("KEYCODE_SEARCH"),
        "channel_up" => Some("KEYCODE_CHANNEL_UP"),
        "channel_down" => Some("KEYCODE_CHANNEL_DOWN"),
        "guide" => Some("KEYCODE_GUIDE"),
        "screensaver" | "sleep" => Some("KEYCODE_SLEEP"),
        "wake" => Some("KEYCODE_WAKEUP"),
        _ => None,
    }
}

impl AndroidAdbDelegate {
    pub fn new(host: String, port: u16, mouse_mode: bool) -> Self {
        Self {
            host,
            port,
            mouse_mode,
            shell: Arc::new(Mutex::new(None)),
            screen_size: Arc::new(Mutex::new(None)),
            pointer: Arc::new(Mutex::new((960.0, 540.0))),
        }
    }

    fn serial(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    async fn connect(&self) -> bool {
        let serial = self.serial();
        info!("[Android ADB] connecting to {serial}...");
        let output = match Command::new("adb")
            .args(["connect", &serial])
            .output()
            .await
        {
            Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
            Err(e) => {
                error!("[Android ADB] failed to execute `adb`: {e}. Is adb installed?");
                return false;
            }
        };

        if output.contains("connected") {
            info!("[Android ADB] connected to {serial}");
            true
        } else {
            warn!("[Android ADB] connection output: {}", output.trim());
            output.contains("already connected")
        }
    }

    async fn ensure_shell(&self) -> Result<(), String> {
        let mut shell_guard = self.shell.lock().await;
        if shell_guard.is_some() {
            return Ok(());
        }

        if !self.connect().await {
            return Err(format!("cannot reach Android TV at {}", self.serial()));
        }

        let serial = self.serial();
        let mut child = Command::new("adb")
            .args(["-s", &serial, "shell"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("failed to spawn adb shell: {e}"))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "failed to capture child stdin".to_string())?;

        *shell_guard = Some(stdin);
        info!("[Android ADB] persistent adb shell session opened");
        Ok(())
    }

    async fn write_shell_line(&self, line: &str) {
        if let Err(e) = self.ensure_shell().await {
            warn!("[Android ADB] {e}");
            return;
        }

        let mut shell_guard = self.shell.lock().await;
        if let Some(stdin) = shell_guard.as_mut() {
            let cmd = format!("{line}\n");
            if let Err(e) = stdin.write_all(cmd.as_bytes()).await {
                warn!("[Android ADB] broken pipe: {e}, resetting shell");
                *shell_guard = None;
            } else {
                let _ = stdin.flush().await;
            }
        }
    }

    async fn send_keyevent(&self, keycode: &str) {
        info!("[Android ADB] sending keyevent: {keycode}");
        self.write_shell_line(&format!("input keyevent {keycode}")).await;
    }

    async fn send_roll(&self, dx: f64, dy: f64) {
        let sensitivity = 1.5;
        let px = dx * sensitivity;
        let py = dy * sensitivity;
        self.write_shell_line(&format!("input roll {px:.0} {py:.0}")).await;
    }

    async fn send_tap(&self) {
        let (x, y) = *self.pointer.lock().await;
        info!("[Android ADB] tap at ({x:.0}, {y:.0})");
        self.write_shell_line(&format!("input tap {x:.0} {y:.0}")).await;
    }
}

impl AtvDelegate for AndroidAdbDelegate {
    fn on_button(&self, name: &str) {
        let keycode = keycode_for_button(name);
        let this = self.clone_ref();
        let name_owned = name.to_string();
        tokio::spawn(async move {
            if let Some(kc) = keycode {
                this.send_keyevent(kc).await;
            } else {
                warn!("[Android ADB] unmapped button: {name_owned}");
            }
        });
    }

    fn on_touch(&self, dx: f64, dy: f64, phase: TouchPhase) {
        if self.mouse_mode && phase == TouchPhase::Moved {
            let this = self.clone_ref();
            tokio::spawn(async move {
                this.send_roll(dx, dy).await;
            });
        }
    }

    fn on_audio(&self, volume: f64, muted: bool) {
        info!("[Android ADB] audio status: vol={volume:.2} muted={muted}");
    }

    fn on_event(&self, kind: EventKind, detail: &str) {
        match kind {
            EventKind::MouseClick => {
                let this = self.clone_ref();
                tokio::spawn(async move {
                    this.send_tap().await;
                });
            }
            _ => {
                info!("[Android ADB] event: {kind:?} {detail}");
            }
        }
    }
}

impl AndroidAdbDelegate {
    fn clone_ref(&self) -> Self {
        Self {
            host: self.host.clone(),
            port: self.port,
            mouse_mode: self.mouse_mode,
            shell: self.shell.clone(),
            screen_size: self.screen_size.clone(),
            pointer: self.pointer.clone(),
        }
    }
}
