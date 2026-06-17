use std::sync::mpsc;
use std::time::Duration;

fn main() {
    println!("[GUARDIAN] Watchdog agent starting up...");
    let (tx, rx) = mpsc::channel();

    // Start background thread monitoring tracker.exe
    let _handle = common::start_watchdog(
        "guardian".to_string(),
        "tracker.exe".to_string(),
        Duration::from_millis(500),
        tx,
    );

    // Process events from the watchdog thread
    while let Ok(event) = rx.recv() {
        println!("[GUARDIAN] Event: {:?}", event);
    }
}
