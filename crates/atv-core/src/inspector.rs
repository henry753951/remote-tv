//! Real-time Inspector and Debug UI hub.
//!
//! Collects operations (buttons, touches, volume, auth/lifecycle state)
//! and broadcasts them over Server-Sent Events (SSE) to connected web browsers.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

const HISTORY_MAX_LEN: usize = 100;

pub struct InspectorHub {
    sequence: AtomicU64,
    history: Mutex<VecDeque<String>>,
    tx: broadcast::Sender<String>,
    connected_clients: Mutex<HashSet<String>>,
    active_sessions: AtomicUsize,
}

impl InspectorHub {
    pub fn new() -> Arc<Self> {
        let (tx, _) = broadcast::channel(256);
        Arc::new(Self {
            sequence: AtomicU64::new(0),
            history: Mutex::new(VecDeque::with_capacity(HISTORY_MAX_LEN)),
            tx,
            connected_clients: Mutex::new(HashSet::new()),
            active_sessions: AtomicUsize::new(0),
        })
    }

    pub fn add_client(&self, peer: &str) {
        if let Ok(mut clients) = self.connected_clients.lock() {
            clients.insert(peer.to_string());
        }
    }

    pub fn remove_client(&self, peer: &str) {
        if let Ok(mut clients) = self.connected_clients.lock() {
            clients.remove(peer);
        }
    }

    pub fn session_started(&self) {
        self.active_sessions.fetch_add(1, Ordering::SeqCst);
    }

    pub fn session_stopped(&self) {
        self.active_sessions
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |val| {
                Some(val.saturating_sub(1))
            })
            .ok();
    }

    pub fn set_client_connected(&self, peer: Option<&str>) {
        match peer {
            Some(p) => self.add_client(p),
            None => {
                if let Ok(mut clients) = self.connected_clients.lock() {
                    clients.clear();
                }
                self.active_sessions.store(0, Ordering::SeqCst);
            }
        }
    }

    pub fn set_session_ready(&self, ready: bool) {
        if ready {
            self.session_started();
        } else {
            self.session_stopped();
        }
    }

    pub fn get_client_info(&self) -> (bool, Option<String>, bool) {
        let clients = self.connected_clients.lock().ok();
        let connected_list: Vec<String> = clients
            .map(|c| c.iter().cloned().collect())
            .unwrap_or_default();
        let connected = !connected_list.is_empty();
        let peer_summary = if connected_list.is_empty() {
            None
        } else if connected_list.len() == 1 {
            Some(connected_list[0].clone())
        } else {
            Some(format!(
                "{} ({} clients)",
                connected_list.join(", "),
                connected_list.len()
            ))
        };
        let ready = self.active_sessions.load(Ordering::SeqCst) > 0;
        (connected, peer_summary, ready)
    }

    /// Emit an event with JSON payload to all connected debug clients.
    pub fn emit(&self, event: &str, data_json: &str) {
        if self.tx.receiver_count() == 0 {
            return;
        }
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let now = chrono_timestamp();
        let packet = format!(
            "{{\"sequence\":{seq},\"timestamp\":\"{now}\",\"event\":\"{event}\",\"data\":{data_json}}}"
        );

        if let Ok(mut hist) = self.history.lock() {
            if hist.len() >= HISTORY_MAX_LEN {
                hist.pop_front();
            }
            hist.push_back(packet.clone());
        }

        let _ = self.tx.send(packet);
    }

    /// Subscribe to the live event stream, receiving recent history first.
    pub fn subscribe(&self) -> (Vec<String>, broadcast::Receiver<String>) {
        let hist = self
            .history
            .lock()
            .map(|h| h.iter().cloned().collect())
            .unwrap_or_default();
        let rx = self.tx.subscribe();
        (hist, rx)
    }
}

fn chrono_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    // Simple ISO 8601 formatting without extra external crate
    let hours = (secs / 3600) % 24;
    let mins = (secs / 60) % 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}.{:03}", hours, mins, s, millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_client_lifecycle() {
        let hub = InspectorHub::new();
        let (conn, peer, ready) = hub.get_client_info();
        assert!(!conn);
        assert!(peer.is_none());
        assert!(!ready);

        // Client 1 connects
        hub.add_client("192.0.2.100:50000");
        let (conn, peer, ready) = hub.get_client_info();
        assert!(conn);
        assert_eq!(peer.as_deref(), Some("192.0.2.100:50000"));
        assert!(!ready);

        // Client 1 starts session
        hub.session_started();
        let (conn, _, ready) = hub.get_client_info();
        assert!(conn);
        assert!(ready);

        // Client 2 connects
        hub.add_client("192.0.2.101:50002");
        let (conn, peer, ready) = hub.get_client_info();
        assert!(conn);
        assert!(ready);
        let p_str = peer.unwrap();
        assert!(p_str.contains("2 clients"));

        // Client 2 starts session
        hub.session_started();
        assert_eq!(hub.active_sessions.load(Ordering::SeqCst), 2);

        // Client 1 disconnects
        hub.remove_client("192.0.2.100:50000");
        hub.session_stopped();

        // Client 2 should STILL be connected and active!
        let (conn, peer, ready) = hub.get_client_info();
        assert!(conn);
        assert_eq!(peer.as_deref(), Some("192.0.2.101:50002"));
        assert!(ready);
        assert_eq!(hub.active_sessions.load(Ordering::SeqCst), 1);

        // Client 2 disconnects
        hub.remove_client("192.0.2.101:50002");
        hub.session_stopped();

        let (conn, peer, ready) = hub.get_client_info();
        assert!(!conn);
        assert!(peer.is_none());
        assert!(!ready);
        assert_eq!(hub.active_sessions.load(Ordering::SeqCst), 0);
    }
}
