use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;
use fs2::FileExt;

use windows::core::PWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Accessibility::{
    SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetClassNameW, GetMessageW, GetWindowLongPtrW,
    GetWindowThreadProcessId, TranslateMessage, EVENT_SYSTEM_FOREGROUND, GWL_STYLE,
    MSG, WINEVENT_OUTOFCONTEXT,
};

// Thread-safe memory structure to log foreground window executable names
static LOGGED_PROCESSES: Mutex<Vec<String>> = Mutex::new(Vec::new());

unsafe extern "system" fn wineventproc(
    _hwineventhook: HWINEVENTHOOK,
    _event: u32,
    hwnd: HWND,
    _idobject: i32,
    _idchild: i32,
    _ideventthread: u32,
    _dwmseventtime: u32,
) {
    if hwnd.0.is_null() {
        return;
    }

    unsafe {
        // 1. Get Window Class Name
        let mut class_name = [0u16; 256];
        let len = GetClassNameW(hwnd, &mut class_name);
        if len == 0 {
            return;
        }
        let class_name_str = String::from_utf16_lossy(&class_name[..len as usize]);

        // Filter out system UI handles
        if class_name_str == "Shell_TrayWnd"
            || class_name_str == "Progman"
            || class_name_str == "WorkerW"
            || class_name_str == "Windows.UI.Core.CoreWindow"
        {
            return;
        }

        // 2. Get Window Style using GetWindowLongPtrW
        let style = GetWindowLongPtrW(hwnd, GWL_STYLE);
        if style == 0 {
            return;
        }

        // 3. Get Process ID & Executable Name
        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid == 0 {
            return;
        }

        if let Ok(process_handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            let mut buffer = [0u16; 1024];
            let mut size = buffer.len() as u32;
            let success = QueryFullProcessImageNameW(
                process_handle,
                PROCESS_NAME_FORMAT(0),
                PWSTR(buffer.as_mut_ptr()),
                &mut size,
            );
            let _ = windows::Win32::Foundation::CloseHandle(process_handle);

            if success.is_ok() {
                let full_path = String::from_utf16_lossy(&buffer[..size as usize]);
                if let Some(exe_name) = Path::new(&full_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                {
                    // Filter out explorer.exe (System Shell)
                    if exe_name.eq_ignore_ascii_case("explorer.exe") {
                        return;
                    }

                    // Log window changes to local memory structure
                    let mut logged = LOGGED_PROCESSES.lock().unwrap();
                    if logged.last().is_none_or(|last| last != exe_name) {
                        logged.push(exe_name.to_string());
                        println!(
                            "[TRACKER] Foreground Window: {} (Class: {}, Style: 0x{:X})",
                            exe_name, class_name_str, style
                        );
                    }
                }
            }
        }
    }
}

/// Helper to get the current user idle time in milliseconds using GetLastInputInfo.
fn get_user_idle_ms() -> Option<u32> {
    let mut lii = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    unsafe {
        if GetLastInputInfo(&mut lii).as_bool() {
            let current_tick = GetTickCount();
            Some(current_tick.wrapping_sub(lii.dwTime))
        } else {
            None
        }
    }
}

/// Manages monotonic active tracking time
struct ActiveTracker {
    last_check: std::time::Instant,
    total_active_duration: Duration,
}

impl ActiveTracker {
    fn new() -> Self {
        Self {
            last_check: std::time::Instant::now(),
            total_active_duration: Duration::from_secs(0),
        }
    }

    fn tick(&mut self, is_idle: bool) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_check);
        self.last_check = now;

        if !is_idle {
            self.total_active_duration += elapsed;
            println!(
                "[TRACKER] User Active. Elapsed: {:.2}s. Total Monotonic Active Time: {:.2}s",
                elapsed.as_secs_f64(),
                self.total_active_duration.as_secs_f64()
            );
        } else {
            println!(
                "[TRACKER] User Idle (>= 3m). Active tracking paused. Total Monotonic Active Time: {:.2}s",
                self.total_active_duration.as_secs_f64()
            );
        }
    }
}

fn main() {
    println!("[TRACKER] Watchdog agent starting up...");

    // Enforce exclusive file lock on config.json
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

    // Start background thread for Win32 window event hook and message loop
    std::thread::spawn(|| unsafe {
        let hook = SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND,
            EVENT_SYSTEM_FOREGROUND,
            None,
            Some(wineventproc),
            0,
            0,
            WINEVENT_OUTOFCONTEXT,
        );

        if hook.0.is_null() {
            eprintln!("[TRACKER] Failed to register WinEventHook");
            return;
        }

        println!("[TRACKER] WinEventHook registered, starting message loop...");

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        let _ = UnhookWinEvent(hook);
    });

    let (tx, rx) = mpsc::channel();

    // Start background thread monitoring guardian.exe
    let _handle = common::start_watchdog(
        "tracker".to_string(),
        "guardian.exe".to_string(),
        Duration::from_millis(500),
        tx,
    );

    let mut tracker = ActiveTracker::new();

    // Event loop in the main thread with a 1-second timeout
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(event) => {
                println!("[TRACKER] Event: {:?}", event);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Periodically check idle state and tick the tracker
                let idle_ms = get_user_idle_ms().unwrap_or(0);
                // 3 minutes threshold (180,000 ms)
                let is_idle = idle_ms >= 180_000;
                tracker.tick(is_idle);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                println!("[TRACKER] Watchdog channel disconnected. Exiting loop.");
                break;
            }
        }
    }
}
