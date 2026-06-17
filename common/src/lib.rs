use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::process::{Child, Command};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

pub type HANDLE = *mut std::ffi::c_void;
pub type DWORD = u32;
pub type BOOL = i32;
pub type WCHAR = u16;

#[allow(non_snake_case)]
#[repr(C)]
pub struct PROCESSENTRY32W {
    pub dwSize: DWORD,
    pub cntUsage: DWORD,
    pub th32ProcessID: DWORD,
    pub th32DefaultHeapID: usize,
    pub th32ModuleID: DWORD,
    pub cntThreads: DWORD,
    pub th32ParentProcessID: DWORD,
    pub pcPriClassBase: i32,
    pub dwFlags: DWORD,
    pub szExeFile: [WCHAR; 260],
}

const TH32CS_SNAPPROCESS: DWORD = 0x00000002;
const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

#[allow(non_camel_case_types, non_snake_case)]
pub type PHANDLER_ROUTINE = unsafe extern "system" fn(dwCtrlType: DWORD) -> BOOL;

unsafe extern "system" {
    fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) -> HANDLE;
    fn Process32FirstW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
    fn Process32NextW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
    fn SetConsoleCtrlHandler(HandlerRoutine: Option<PHANDLER_ROUTINE>, Add: BOOL) -> BOOL;
}

unsafe extern "system" fn ctrl_handler(_ctrl_type: DWORD) -> BOOL {
    // Exit cleanly with code 0 so the companion knows we intended to stop
    std::process::exit(0);
}

/// Registers a custom console control handler that exits cleanly on Ctrl+C / close signals.
pub fn setup_ctrl_handler() {
    unsafe {
        SetConsoleCtrlHandler(Some(ctrl_handler), 1);
    }
}

/// Check if a process is running by its executable name (case-insensitive).
pub fn is_process_running(name: &str) -> bool {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return false;
        }

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as DWORD,
            cntUsage: 0,
            th32ProcessID: 0,
            th32DefaultHeapID: 0,
            th32ModuleID: 0,
            cntThreads: 0,
            th32ParentProcessID: 0,
            pcPriClassBase: 0,
            dwFlags: 0,
            szExeFile: [0; 260],
        };

        if Process32FirstW(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            return false;
        }

        loop {
            let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
            let exe_name_os = OsString::from_wide(&entry.szExeFile[..len]);
            if exe_name_os.to_str().is_some_and(|s| s.eq_ignore_ascii_case(name)) {
                CloseHandle(snapshot);
                return true;
            }

            if Process32NextW(snapshot, &mut entry) == 0 {
                break;
            }
        }

        CloseHandle(snapshot);
        false
    }
}

/// Spawn a process with the given target name, located in the same directory as the current executable.
pub fn spawn_process(target_name: &str, args: &[String]) -> std::io::Result<Child> {
    let mut exe_path = std::env::current_exe()?;
    exe_path.set_file_name(target_name);
    Command::new(exe_path).args(args).spawn()
}

/// Watchdog events sent via mpsc channel.
#[derive(Debug)]
pub enum WatchdogEvent {
    Started(String),
    ProcessDetected(String),
    ProcessMissing(String),
    ProcessSpawned(String),
    ProcessSpawnFailed(String, String),
    ProcessExited(String, String),
}

/// Start the watchdog thread that monitors `target_name` and spawns it if it goes down.
pub fn start_watchdog(
    my_name: String,
    target_name: String,
    interval: Duration,
    enable_kill: bool,
    tx: Sender<WatchdogEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let _ = tx.send(WatchdogEvent::Started(my_name.clone()));
        let mut child: Option<Child> = None;
        let mut last_was_running = false;

        loop {
            let mut needs_spawn = false;

            if let Some(ref mut c) = child {
                match c.try_wait() {
                    Ok(Some(status)) => {
                        let status_str = status.to_string();
                        let _ = tx.send(WatchdogEvent::ProcessExited(target_name.clone(), status_str));
                        child = None;
                        if enable_kill && status.success() {
                            println!("[{}] Companion exited cleanly. Exiting watchdog.", my_name);
                            std::process::exit(0);
                        }
                        needs_spawn = true;
                    }
                    Ok(None) => {
                        // Still running
                        last_was_running = true;
                    }
                    Err(e) => {
                        let _ = tx.send(WatchdogEvent::ProcessExited(
                            target_name.clone(),
                            format!("Error waiting: {}", e),
                        ));
                        child = None;
                        needs_spawn = true;
                    }
                }
            } else {
                let is_running = is_process_running(&target_name);
                if is_running {
                    if !last_was_running {
                        let _ = tx.send(WatchdogEvent::ProcessDetected(target_name.clone()));
                        last_was_running = true;
                    }
                } else {
                    if last_was_running || child.is_none() {
                        let _ = tx.send(WatchdogEvent::ProcessMissing(target_name.clone()));
                    }
                    last_was_running = false;
                    needs_spawn = true;
                }
            }

            if needs_spawn {
                let child_args = if enable_kill {
                    vec!["--enable-kill".to_string()]
                } else {
                    vec![]
                };
                match spawn_process(&target_name, &child_args) {
                    Ok(c) => {
                        let _ = tx.send(WatchdogEvent::ProcessSpawned(target_name.clone()));
                        child = Some(c);
                        last_was_running = true;
                    }
                    Err(e) => {
                        let _ = tx.send(WatchdogEvent::ProcessSpawnFailed(target_name.clone(), e.to_string()));
                        last_was_running = false;
                    }
                }
            }

            thread::sleep(interval);
        }
    })
}
