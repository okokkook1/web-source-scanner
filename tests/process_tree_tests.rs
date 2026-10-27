#![cfg(windows)]
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use web_source_scanner::engine::{run_process, spawn_paused};

fn helper() -> &'static PathBuf {
    static BUILD: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();
    &BUILD
        .get_or_init(|| {
            let dir = tempfile::tempdir().unwrap();
            let exe = dir.path().join("child.exe");
            let result = Command::new("rustc")
                .arg(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/fixtures/process_child.rs"),
                )
                .args(["--edition", "2024", "-o"])
                .arg(&exe)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            (dir, exe)
        })
        .1
}

#[test]
fn child_cannot_execute_before_job_assignment_and_explicit_resume() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("started");
    let mut cmd = Command::new(helper());
    cmd.arg(&marker);
    let mut paused = spawn_paused(cmd).unwrap();
    thread::sleep(Duration::from_millis(300));
    let ran_early = marker.exists();
    if ran_early {
        paused.terminate();
    }
    assert!(
        !ran_early,
        "engine executed before explicit resume; child can escape job attachment window"
    );
    paused.resume().unwrap();
    let begin = Instant::now();
    while !marker.exists() && begin.elapsed() < Duration::from_secs(2) {
        thread::sleep(Duration::from_millis(10));
    }
    let ran = marker.exists();
    paused.terminate();
    assert!(ran, "process did not execute after resume");
}

#[test]
fn running_cancellation_and_timeout_stop_actual_descendant_processes() {
    for do_cancel in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("parent");
        let pidfile = marker.with_extension("pid");
        let mut cmd = Command::new(helper());
        cmd.arg(&marker).arg("parent");
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = cancel.clone();
        let ready = pidfile.clone();
        let control = thread::spawn(move || {
            let begin = Instant::now();
            while !ready.exists() && begin.elapsed() < Duration::from_secs(4) {
                thread::sleep(Duration::from_millis(5));
            }
            if do_cancel {
                signal.store(true, Ordering::Relaxed);
            }
        });
        let result = run_process(cmd, &cancel, 2).unwrap();
        control.join().unwrap();
        assert!(pidfile.exists(), "helper did not create descendant");
        assert_eq!(result.cancelled, do_cancel);
        assert_eq!(result.timed_out, !do_cancel);
        let pid = fs::read_to_string(pidfile)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        unsafe {
            use windows_sys::Win32::{
                Foundation::{CloseHandle, WAIT_OBJECT_0},
                System::Threading::{OpenProcess, WaitForSingleObject},
            };
            let process = OpenProcess(0x00100000, 0, pid);
            if !process.is_null() {
                let state = WaitForSingleObject(process, 2000);
                CloseHandle(process);
                assert_eq!(
                    state, WAIT_OBJECT_0,
                    "descendant remains alive after cancel/timeout"
                );
            }
        }
    }
}
