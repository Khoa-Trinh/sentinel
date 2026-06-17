use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;
use fs2::FileExt;

use windows::core::PWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Accessibility::{
    SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK,
};
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

    // Process events from the watchdog thread
    while let Ok(event) = rx.recv() {
        println!("[TRACKER] Event: {:?}", event);
    }
}
