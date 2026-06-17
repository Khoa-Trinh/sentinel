use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use std::sync::mpsc;
use std::time::Duration;
use fs2::FileExt;

fn main() {
    println!("[TRACKER] Watchdog agent starting up...");

    // Enforce exclusive file lock on config.json
    // FILE_SHARE_READ (1) | FILE_SHARE_WRITE (2) excludes FILE_SHARE_DELETE (4),
    // ensuring that Windows throws a "File In Use" error if deletion is attempted.
    let _config_file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .share_mode(1 | 2)
        .open("config.json")
    {
        Ok(file) => {
            match file.try_lock_exclusive() {
                Ok(_) => {
                    println!("[TRACKER] Successfully acquired exclusive lock on config.json");
                    Some(file)
                }
                Err(e) => {
                    eprintln!("[TRACKER] Failed to acquire lock on config.json: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            eprintln!("[TRACKER] Failed to create/open config.json: {}", e);
            None
        }
    };

    let (tx, rx) = mpsc::channel();

    // Start background thread monitoring guardian.exe
    let _handle = common::start_watchdog(
        "tracker".to_string(),
        "guardian.exe".to_string(),
        Duration::from_millis(500),
        tx,
    );

    // Process events from the watchdog thread
    while let Ok(event) = rx.recv() {
        println!("[TRACKER] Event: {:?}", event);
    }
}
