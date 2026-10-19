//! Print delegate: observes events and prints them to stdout.

use atv_core::{AtvDelegate, EventKind, TouchPhase};

pub struct PrintDelegate;

impl AtvDelegate for PrintDelegate {
    fn on_button(&self, name: &str) {
        println!("on_button name={name}");
    }

    fn on_touch(&self, dx: f64, dy: f64, phase: TouchPhase) {
        println!("on_touch dx={dx:.1} dy={dy:.1} phase={phase:?}");
    }

    fn on_audio(&self, volume: f64, muted: bool) {
        println!("on_audio volume={volume:.4} muted={muted}");
    }

    fn on_event(&self, kind: EventKind, detail: &str) {
        println!("on_event kind={kind:?} detail={detail}");
    }
}
