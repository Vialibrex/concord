//! Graceful shutdown of `concord-bench run` on SIGTERM: stops active trials, saves partial
//! results and exits with code 2 instead of dying by signal.

#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "test SOCKS5 relay stands for an external proxy peer, not a core socket"
)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const BENCH: &str = env!("CARGO_BIN_EXE_concord-bench");

struct CleanupGuard {
    child: Option<Child>,
    out: PathBuf,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.out);
    }
}

fn relay_socks5(mut client: TcpStream) {
    let mut head = [0u8; 2];
    if client.read_exact(&mut head).is_err() || head[0] != 5 {
        return;
    }
    let mut methods = vec![0u8; head[1] as usize];
    if client.read_exact(&mut methods).is_err() || client.write_all(&[5, 0]).is_err() {
        return;
    }
    let mut req = [0u8; 4];
    if client.read_exact(&mut req).is_err() || req[1] != 1 || req[3] != 1 {
        return;
    }
    let mut addr = [0u8; 6];
    if client.read_exact(&mut addr).is_err() {
        return;
    }
    let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
    let port = u16::from_be_bytes([addr[4], addr[5]]);
    let Ok(mut remote) = TcpStream::connect(SocketAddr::from((ip, port))) else {
        return;
    };
    if client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).is_err() {
        return;
    }
    let (Ok(mut c_read), Ok(mut r_write)) = (client.try_clone(), remote.try_clone()) else {
        return;
    };
    let up = thread::spawn(move || {
        let _ = std::io::copy(&mut c_read, &mut r_write);
    });
    let _ = std::io::copy(&mut remote, &mut client);
    let _ = up.join();
}

#[test]
fn run_shuts_down_gracefully_and_saves_results_on_sigterm() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let socks_addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (accepted_bg, stop_bg) = (accepted.clone(), stop.clone());
    let server = thread::spawn(move || {
        while !stop_bg.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    accepted_bg.fetch_add(1, Ordering::Relaxed);
                    thread::spawn(move || relay_socks5(stream));
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let out = std::env::temp_dir().join(format!("concord-bench-sigterm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let child = Command::new(BENCH)
        .args([
            "run",
            "--attach",
            &format!("self=pid:{}", std::process::id()),
            "--via",
            &format!("socks:{socks_addr}"),
            "--workloads",
            "tcp-down",
            "--rounds",
            "1",
            "--duration",
            "30",
            "--warmup",
            "1",
            "--out",
            out.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut guard = CleanupGuard {
        child: Some(child),
        out: out.clone(),
    };

    // First connection is echo_once readiness; second connection means the workload has started.
    let wait_start = Instant::now();
    while accepted.load(Ordering::Relaxed) < 2 {
        assert!(
            guard.child.as_mut().unwrap().try_wait().unwrap().is_none(),
            "concord-bench exited before starting workload"
        );
        assert!(
            wait_start.elapsed() < Duration::from_secs(15),
            "timed out waiting for concord-bench to open workload flow"
        );
        thread::sleep(Duration::from_millis(20));
    }

    let pid = guard.child.as_ref().unwrap().id();
    let kill = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .unwrap();
    assert!(kill.success());

    let term_start = Instant::now();
    while guard.child.as_mut().unwrap().try_wait().unwrap().is_none() {
        assert!(
            term_start.elapsed() < Duration::from_secs(5),
            "concord-bench did not exit promptly after SIGTERM"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let output = guard.child.take().unwrap().wait_with_output().unwrap();
    stop.store(true, Ordering::Relaxed);
    let _ = server.join();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected graceful exit code 2, got {:?}; stderr:\n{stderr}",
        output.status
    );
    assert!(
        stderr.contains("terminated; partial results kept"),
        "expected SIGTERM shutdown message in stderr:\n{stderr}"
    );
    let results_path = out.join("results.json");
    let raw = std::fs::read_to_string(&results_path)
        .unwrap_or_else(|e| panic!("missing {}: {e}", results_path.display()));
    let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(
        json["finished"].as_str().is_some(),
        "expected finished timestamp in results.json after teardown"
    );
    assert!(out.join("report.md").is_file());
}
