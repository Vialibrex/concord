//! The busy loop behind `run --keep-awake` on macOS: the priority it runs at, and that it ends
//! once the harness lets go of its stdin.

#![cfg(target_os = "macos")]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BENCH: &str = env!("CARGO_BIN_EXE_concord-bench");

fn spinning() -> Child {
    let mut child = Command::new(BENCH)
        .args(["spin", "--cpu", "0", "--parent", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "spinning");
    child
}

fn nice(pid: u32) -> String {
    let out = Command::new("ps")
        .args(["-o", "nice=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn the_loop_runs_at_nice_20() {
    let mut child = spinning();

    assert_eq!(nice(child.id()), "20");

    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn the_loop_ends_when_its_stdin_closes() {
    let mut child = spinning();
    drop(child.stdin.take());

    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(20));
    }
}
