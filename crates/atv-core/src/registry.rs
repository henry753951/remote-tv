//! Device registry and active session tracking for Apple TV Companion protocol.
//!
//! Maintains known devices, their stable `remote_session_id`, and manages
//! single active connection per device/IP with instant preemption.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tracing::info;

/// Information about a previously seen device.
#[derive(Clone, Debug)]
pub struct DeviceRecord {
    pub device_id: String,
    pub name: String,
    pub model: String,
    pub remote_session_id: u32,
    pub last_seen: Instant,
}

/// Registry of paired/known companion devices.
/// Retains device state and session IDs across reconnections with a 24-hour TTL.
pub struct DeviceRegistry {
    devices: HashMap<String, DeviceRecord>,
    aliases: HashMap<String, String>,
    ttl: Duration,
}

impl DeviceRegistry {
    pub fn new(ttl: Duration) -> Self {
        Self {
            devices: HashMap::new(),
            aliases: HashMap::new(),
            ttl,
        }
    }

    /// Evicts records that have been idle longer than the TTL.
    pub fn clean_expired(&mut self) {
        let now = Instant::now();
        let ttl = self.ttl;
        let expired: Vec<String> = self
            .devices
            .iter()
            .filter(|(_, d)| now.duration_since(d.last_seen) > ttl)
            .map(|(k, _)| k.clone())
            .collect();

        for k in expired {
            if let Some(dev) = self.devices.remove(&k) {
                info!(
                    "[REGISTRY] expired device {k} ({}) after 24h idle",
                    dev.name
                );
            }
        }
        self.aliases.retain(|_, v| self.devices.contains_key(v));
    }

    /// Looks up an existing device or registers a new one.
    /// Returns `(remote_session_id, is_renewed)`.
    pub fn get_or_register(
        &mut self,
        primary_id: &str,
        alias_id: Option<&str>,
        name: &str,
        model: &str,
    ) -> (u32, bool) {
        self.clean_expired();
        let now = Instant::now();

        // Check if primary_id exists, or if primary_id or alias_id is a registered alias
        let target_key = if self.devices.contains_key(primary_id) {
            Some(primary_id.to_string())
        } else if let Some(canonical) = self.aliases.get(primary_id) {
            Some(canonical.clone())
        } else if let Some(canonical) = alias_id.and_then(|a| self.aliases.get(a)) {
            Some(canonical.clone())
        } else {
            None
        };

        if let Some(key) = target_key {
            let dev = self.devices.get_mut(&key).unwrap();
            dev.last_seen = now;
            if !name.is_empty() {
                dev.name = name.to_string();
            }
            if !model.is_empty() {
                dev.model = model.to_string();
            }
            if let Some(alias) = alias_id {
                self.aliases.insert(alias.to_string(), key.clone());
            }
            info!(
                "[REGISTRY] renewed device {key} ({}) session={}",
                dev.name, dev.remote_session_id
            );
            (dev.remote_session_id, true)
        } else {
            let remote_session_id: u32 = rand::random();
            let record = DeviceRecord {
                device_id: primary_id.to_string(),
                name: name.to_string(),
                model: model.to_string(),
                remote_session_id,
                last_seen: now,
            };
            self.devices.insert(primary_id.to_string(), record);
            if let Some(alias) = alias_id {
                self.aliases.insert(alias.to_string(), primary_id.to_string());
            }
            info!(
                "[REGISTRY] registered new device {primary_id} ({name}) session={remote_session_id}"
            );
            (remote_session_id, false)
        }
    }
}

/// Metadata for an active companion TCP connection.
pub struct ActiveConnection {
    pub id: u64,
    pub peer_ip: IpAddr,
    pub device_id: Option<String>,
    pub session_established: Arc<AtomicBool>,
    pub abort_tx: watch::Sender<bool>,
}

/// Tracks all live companion connections to enforce single active session
/// and instant preemption.
#[derive(Default)]
pub struct ActiveConnectionTracker {
    next_id: u64,
    connections: Vec<ActiveConnection>,
}

impl ActiveConnectionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a new connection. Automatically aborts any prior unestablished
    /// connections from the same IP.
    pub fn register(
        &mut self,
        peer_ip: IpAddr,
        session_established: Arc<AtomicBool>,
    ) -> (u64, watch::Receiver<bool>) {
        // Abort unestablished connections from the same IP
        for conn in &self.connections {
            if conn.peer_ip == peer_ip && !conn.session_established.load(Ordering::SeqCst) {
                info!(
                    "aborting unestablished previous connection from {peer_ip} for new incoming connection"
                );
                let _ = conn.abort_tx.send(true);
            }
        }

        self.next_id += 1;
        let id = self.next_id;
        let (abort_tx, abort_rx) = watch::channel(false);
        self.connections.push(ActiveConnection {
            id,
            peer_ip,
            device_id: None,
            session_established,
            abort_tx,
        });

        (id, abort_rx)
    }

    /// Associates an identified device with a connection. Aborts any other
    /// connections for the same device.
    pub fn set_device_id(&mut self, conn_id: u64, device_id: &str) {
        for conn in &self.connections {
            if conn.id != conn_id && conn.device_id.as_deref() == Some(device_id) {
                info!("[REGISTRY] closing superseded connection for device {device_id}");
                let _ = conn.abort_tx.send(true);
            }
        }

        if let Some(conn) = self.connections.iter_mut().find(|c| c.id == conn_id) {
            conn.device_id = Some(device_id.to_string());
        }
    }

    /// Removes a terminated connection.
    pub fn unregister(&mut self, conn_id: u64) {
        self.connections.retain(|c| c.id != conn_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_device_registry_session_renewal_and_aliasing() {
        let mut reg = DeviceRegistry::new(Duration::from_secs(3600));

        // First registration with idsID
        let (sid1, renewed1) = reg.get_or_register(
            "EE5426A1-FB95-4329-83A4-41F2D767DC28",
            Some("18:3E:E4:EE:ED:40"),
            "MP",
            "iPhone18,1",
        );
        assert!(!renewed1);

        // Second registration with same idsID and rotating pubID
        let (sid2, renewed2) = reg.get_or_register(
            "EE5426A1-FB95-4329-83A4-41F2D767DC28",
            Some("C3:DA:FA:17:6F:DF"),
            "MP",
            "iPhone18,1",
        );
        assert!(renewed2);
        assert_eq!(sid1, sid2, "Session ID must be preserved across reconnections");

        // Third lookup only using the second alias pubID (e.g. if idsID missing)
        let (sid3, renewed3) = reg.get_or_register("C3:DA:FA:17:6F:DF", None, "MP", "iPhone18,1");
        assert!(renewed3);
        assert_eq!(sid1, sid3, "Alias must point to original session ID");
    }

    #[test]
    fn test_active_connection_tracker_preemption() {
        let mut tracker = ActiveConnectionTracker::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 101, 206));

        let established1 = Arc::new(AtomicBool::new(false));
        let (id1, abort_rx1) = tracker.register(ip, established1.clone());
        assert!(!*abort_rx1.borrow());

        // A second connection from the same IP arrives before session 1 established
        let established2 = Arc::new(AtomicBool::new(false));
        let (id2, abort_rx2) = tracker.register(ip, established2.clone());

        // Session 1 must be aborted
        assert!(*abort_rx1.borrow(), "Prior unestablished connection must be aborted");
        assert!(!*abort_rx2.borrow(), "New connection must not be aborted");

        // Session 2 identifies device
        tracker.set_device_id(id2, "EE5426A1-FB95-4329-83A4-41F2D767DC28");
        established2.store(true, Ordering::SeqCst);

        // Later, another connection identifies the same device
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 101, 206));
        let established3 = Arc::new(AtomicBool::new(false));
        let (id3, _abort_rx3) = tracker.register(ip2, established3);
        tracker.set_device_id(id3, "EE5426A1-FB95-4329-83A4-41F2D767DC28");

        // Session 2 must now be superseded
        let mut abort_rx2_mut = abort_rx2;
        assert!(*abort_rx2_mut.borrow_and_update(), "Superseded session must be aborted");

        tracker.unregister(id1);
        tracker.unregister(id2);
        tracker.unregister(id3);
        assert_eq!(tracker.connections.len(), 0);
    }
}
