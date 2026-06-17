use std::sync::mpsc;
use std::time::Duration;

fn main() {
    println!("[GUARDIAN] Watchdog agent starting up...");

    let args: Vec<String> = std::env::args().collect();
    let enable_kill = args.iter().any(|arg| arg == "--enable-kill");

    if enable_kill {
        println!("[GUARDIAN] Enable-kill mode active. Registering Ctrl+C handler...");
        common::setup_ctrl_handler();
    }

    let (tx, rx) = mpsc::channel();

    // Start background thread monitoring tracker.exe
    let _handle = common::start_watchdog(
        "guardian".to_string(),
        "tracker.exe".to_string(),
        Duration::from_millis(500),
        enable_kill,
        tx,
    );

    // Process events from the watchdog thread
    while let Ok(event) = rx.recv() {
        println!("[GUARDIAN] Event: {:?}", event);
    }
}
