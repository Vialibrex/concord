#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "the client and the origin are the test's own, not the core's dials"
)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use concord_test_support::port_to_bind_later;

const BINARY: &str = env!("CARGO_BIN_EXE_concord");
const BODY: &str = "hello from the origin";

fn serve_once(listener: TcpListener) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        while !request.ends_with(b"\r\n\r\n") {
            let read = stream.read(&mut buf).unwrap();
            assert!(read > 0, "the request ended early");
            request.extend_from_slice(&buf[..read]);
        }
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
            BODY.len()
        );
        stream.write_all(reply.as_bytes()).unwrap();
    })
}

fn spawn_run(config: &Path, home: &Path) -> Child {
    Command::new(BINARY)
        .arg("run")
        .arg("-c")
        .arg(config)
        .arg("-d")
        .arg(home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn connect_within(port: u16, child: &mut Child, within: Duration) -> TcpStream {
    let deadline = Instant::now() + within;
    loop {
        if let Ok(stream) = TcpStream::connect((Ipv4Addr::LOCALHOST, port)) {
            return stream;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!(
                "the core exited before listening: {status}\n{}",
                stderr_of(child)
            );
        }
        assert!(Instant::now() < deadline, "nothing listens on {port}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn exit_within(child: &mut Child, within: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

fn stderr_of(child: &mut Child) -> String {
    let mut text = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut text);
    }
    text
}

#[test]
fn run_proxies_through_the_profiles_mixed_listener_and_stops_on_sigterm() {
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let served = serve_once(origin);
    let mixed = port_to_bind_later();
    let profiles = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let config = profiles.path().join("profile.yaml");
    std::fs::write(
        &config,
        format!("mixed-port: {mixed}\nallow-lan: false\nmode: rule\nlog-level: info\nrules:\n  - MATCH,DIRECT\n"),
    )
    .unwrap();

    let mut child = spawn_run(&config, home.path());
    let mut client = connect_within(mixed, &mut child, Duration::from_secs(20));
    write!(
        client,
        "GET http://127.0.0.1:{origin_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut reply = String::new();
    client.read_to_string(&mut reply).unwrap();
    served.join().unwrap();

    // SAFETY: the pid is of a child this test spawned and has not reaped.
    #[allow(unsafe_code, reason = "kill has no safe std wrapper")]
    let signalled = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    let status = exit_within(&mut child, Duration::from_secs(8));
    let stderr = stderr_of(&mut child);

    assert!(reply.ends_with(BODY), "{reply}");
    assert_eq!(signalled, 0);
    assert_eq!(status.and_then(|status| status.code()), Some(0), "{stderr}");
    assert!(home.path().join("config.yaml").exists());
}

#[test]
fn run_refuses_a_profile_it_cannot_load_and_exits_with_one() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join("broken.yaml");
    std::fs::write(&config, "mixed-port: [not a port\n").unwrap();

    let mut child = spawn_run(&config, home.path());
    let status = exit_within(&mut child, Duration::from_secs(20));
    let stderr = stderr_of(&mut child);

    assert_eq!(status.and_then(|status| status.code()), Some(1), "{stderr}");
    assert!(stderr.contains("broken.yaml"), "{stderr}");
    assert!(!home.path().join("config.yaml").exists());
}
