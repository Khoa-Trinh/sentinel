use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;
use fs2::FileExt;

use windows::core::{Interface, PWSTR};
use windows::Win32::Foundation::{HWND, RECT};
use windows::Win32::Media::Audio::{
    eConsole, eRender, IAudioSessionControl2, IAudioSessionManager2,
    IMMDevice, IMMDeviceEnumerator, MMDeviceEnumerator,
};
use windows::Win32::Media::Audio::Endpoints::IAudioMeterInformation;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_MULTITHREADED,
};
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
    DispatchMessageW, GetClassNameW, GetForegroundWindow, GetMessageW, GetWindowLongPtrW,
    GetWindowThreadProcessId, TranslateMessage, EVENT_SYSTEM_FOREGROUND, GWL_STYLE, MSG,
    WINEVENT_OUTOFCONTEXT, GetWindowRect, SetWindowPos, SetForegroundWindow,
    HWND_TOPMOST, SWP_SHOWWINDOW, SWP_HIDEWINDOW, FindWindowW,
};

// Thread-safe wrapper for HWND to allow storage in lazy/global statics
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SendHwnd(HWND);

unsafe impl Send for SendHwnd {}
unsafe impl Sync for SendHwnd {}

// Global states to coordinate lockout overlay
static LOCKOUT_ACTIVE: Mutex<bool> = Mutex::new(false);
static TARGET_HWND: Mutex<SendHwnd> = Mutex::new(SendHwnd(HWND(std::ptr::null_mut())));

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

/// Helper to get the active foreground process ID.
fn get_foreground_process_id() -> u32 {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.0.is_null() {
            return 0;
        }
        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        pid
    }
}

/// Helper to check if the current foreground process is actively streaming audio (peak > 0.0).
fn is_foreground_process_streaming_audio(foreground_pid: u32) -> bool {
    if foreground_pid == 0 {
        return false;
    }

    unsafe {
        // Initialize COM (safe to call repeatedly)
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);

        // Get IMMDeviceEnumerator
        let enumerator: IMMDeviceEnumerator = match CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL) {
            Ok(e) => e,
            Err(_) => return false,
        };

        // Get default audio endpoint device
        let device: IMMDevice = match enumerator.GetDefaultAudioEndpoint(eRender, eConsole) {
            Ok(d) => d,
            Err(_) => return false,
        };

        // Activate IAudioSessionManager2 on the device
        // Activate signature in windows crate takes dwclscontext (u32) and null pointer parameter
        let session_manager: IAudioSessionManager2 = match device.Activate(CLSCTX_ALL, None) {
            Ok(sm) => sm,
            Err(_) => return false,
        };

        // Get session enumerator
        let session_enumerator = match session_manager.GetSessionEnumerator() {
            Ok(se) => se,
            Err(_) => return false,
        };

        let count = match session_enumerator.GetCount() {
            Ok(c) => c,
            Err(_) => return false,
        };

        for i in 0..count {
            let session_control = match session_enumerator.GetSession(i) {
                Ok(sc) => sc,
                Err(_) => continue,
            };

            // Cast to IAudioSessionControl2 to get Process ID
            let session_control2: IAudioSessionControl2 = match session_control.cast() {
                Ok(sc2) => sc2,
                Err(_) => continue,
            };

            let pid = match session_control2.GetProcessId() {
                Ok(p) => p,
                Err(_) => continue,
            };

            if pid == foreground_pid {
                // Cast to IAudioMeterInformation to query peak audio level
                let meter_info: IAudioMeterInformation = match session_control.cast() {
                    Ok(mi) => mi,
                    Err(_) => continue,
                };

                let peak = match meter_info.GetPeakValue() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                if peak > 0.0 {
                    return true;
                }
            }
        }
    }

    false
}

/// Helper to get the egui window handle by its title.
fn get_egui_hwnd() -> Option<HWND> {
    unsafe {
        let title: Vec<u16> = "Sentinel Lockout Overlay\0".encode_utf16().collect();
        FindWindowW(None, windows::core::PCWSTR(title.as_ptr())).ok()
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

struct LockoutOverlayApp;

impl eframe::App for LockoutOverlayApp {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        let is_locked = *LOCKOUT_ACTIVE.lock().unwrap();
        if is_locked {
            [0.12, 0.0, 0.0, 0.7] // Semi-transparent dark red background
        } else {
            [0.0, 0.0, 0.0, 0.0] // Completely transparent
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Request repaint continuously to update overlay positions and transparency
        ui.ctx().request_repaint();

        let is_locked = *LOCKOUT_ACTIVE.lock().unwrap();
        if !is_locked {
            // Keep offscreen or hidden when not locked out
            unsafe {
                if let Some(egui_hwnd) = get_egui_hwnd() {
                    let _ = SetWindowPos(
                        egui_hwnd,
                        None,
                        0,
                        0,
                        0,
                        0,
                        SWP_HIDEWINDOW,
                    );
                }
            }
            return;
        }

        // Lockout is active. Place overlay directly over target application bounds.
        let target = TARGET_HWND.lock().unwrap().0;
        unsafe {
            if let Some(egui_hwnd) = get_egui_hwnd() {
                let mut rect = RECT::default();
                if !target.0.is_null() && GetWindowRect(target, &mut rect).is_ok() {
                    let x = rect.left;
                    let y = rect.top;
                    let w = rect.right - rect.left;
                    let h = rect.bottom - rect.top;
                    let _ = SetWindowPos(
                        egui_hwnd,
                        Some(HWND_TOPMOST),
                        x,
                        y,
                        w,
                        h,
                        SWP_SHOWWINDOW,
                    );
                }
            }
        }

        // Draw lockout UI content centered inside the window
        ui.centered_and_justified(|ui| {
            ui.heading(
                egui::RichText::new("LOCKOUT ACTIVE\nUsage Time Limit Exceeded!")
                    .color(egui::Color32::RED)
                    .size(32.0)
                    .strong()
            );
        });
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

    // Spawn background watchdog and user idle tracker thread
    std::thread::spawn(move || {
        let mut tracker = ActiveTracker::new();

        loop {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(event) => {
                    println!("[TRACKER] Event: {:?}", event);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let idle_ms = get_user_idle_ms().unwrap_or(0);
                    let foreground_pid = get_foreground_process_id();
                    let is_streaming_audio = is_foreground_process_streaming_audio(foreground_pid);
                    let is_idle = idle_ms >= 180_000 && !is_streaming_audio;
                    
                    tracker.tick(is_idle);

                    // Check active usage time limit lockout rule (e.g. 10 seconds active usage)
                    if tracker.total_active_duration >= Duration::from_secs(10) {
                        let mut lockout = LOCKOUT_ACTIVE.lock().unwrap();
                        if !*lockout {
                            *lockout = true;
                            println!("[TRACKER] Lockout rule violated! Activating overlay...");
                            
                            unsafe {
                                let fg_hwnd = GetForegroundWindow();
                                if !fg_hwnd.0.is_null() {
                                    *TARGET_HWND.lock().unwrap() = SendHwnd(fg_hwnd);
                                }
                            }
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    println!("[TRACKER] Watchdog channel disconnected. Exiting loop.");
                    break;
                }
            }
        }
    });

    // Spawn background focus-stealing thread
    std::thread::spawn(|| {
        loop {
            let is_locked = *LOCKOUT_ACTIVE.lock().unwrap();
            let target_hwnd = if is_locked { get_egui_hwnd() } else { None };
            if let Some(egui_hwnd) = target_hwnd {
                let active_hwnd = unsafe { GetForegroundWindow() };
                if active_hwnd != egui_hwnd {
                    unsafe {
                        let _ = SetForegroundWindow(egui_hwnd);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    // Run egui on the main thread
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Sentinel Lockout Overlay")
            .with_decorations(false)
            .with_transparent(true)
            .with_always_on_top()
            .with_active(true),
        ..Default::default()
    };

    let _ = eframe::run_native(
        "Sentinel Lockout Overlay",
        options,
        Box::new(|_cc| Ok(Box::new(LockoutOverlayApp))),
    );
}
