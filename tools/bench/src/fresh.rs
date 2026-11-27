//! Fresh-core workloads: `idle`, `quiet`, `startup` and `large`.

use std::future::Future;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::load::{Ctx, Io, MIB, Metrics, io};
use crate::mitm;
use crate::probe::{self, Window};
use crate::socks;
use crate::syscalls;

/// Holds `ctx.idle_conns` connections, each proven end to end, and reads the core
/// before, while they are held, and after they are closed.
pub async fn idle(ctx: &Ctx) -> Io<Metrics> {
    if ctx.tls.is_some() {
        let held = ctx.clone();
        return hold(ctx, move || mitm::held(held.clone()), drop).await;
    }
    let (entry, target) = (ctx.entry, ctx.at(ctx.ports.echo));
    let open = move || async move {
        let mut stream = socks::connect(entry, target)
            .await
            .map_err(|e| e.to_string())?;
        stream.write_all(b"i").await.map_err(|e| e.to_string())?;
        let mut byte = [0u8; 1];
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| e.to_string())?;
        Ok(stream)
    };
    hold(ctx, open, socks::abort).await
}

/// Holds one proven connection for `ctx.duration` and reads what the otherwise quiet core does: each wait a thread
/// returns from is a voluntary context switch, so switches per minute count its wake-ups.
pub async fn quiet(ctx: &Ctx) -> Io<Metrics> {
    if ctx.tls.is_some() {
        return Err("quiet runs on the plain cases".into());
    }
    let mut stream = socks::connect(ctx.entry, ctx.at(ctx.ports.echo))
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(b"q").await.map_err(io("write"))?;
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte).await.map_err(io("read"))?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let window = Window::open_counting_syscalls(ctx.pids.core);
    tokio::time::sleep(ctx.duration).await;
    let core = window.close();
    socks::abort(stream);
    let minutes = core.wall_ns as f64 / 60e9;
    let mut m = Metrics::new();
    m.insert("cores".into(), core.cores());
    if let Some(switches) = core.context_switches {
        m.insert("ctx_per_min".into(), switches as f64 / minutes);
    }
    if let Some(counts) = core.syscall_counts {
        m.insert("syscalls_per_min".into(), counts.total as f64 / minutes);
        for (name, calls) in syscalls::NAMES.iter().zip(counts.by_name) {
            m.insert(format!("sys_{name}_per_min"), calls as f64 / minutes);
        }
    }
    Ok(m)
}

/// Opens `idle_conns` connections with `open`, 64 at a time, and reads what holding them costs.
async fn hold<T, F, Fut>(ctx: &Ctx, open: F, close: fn(T)) -> Io<Metrics>
where
    T: Send + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = Io<T>> + Send + 'static,
{
    let pid = ctx.pids.core;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let before = probe::memory(pid, true).ok_or("read core memory")?;
    let server_before = ctx.pids.server.and_then(|p| probe::memory(p, true));
    let fds_before = probe::open_fds(pid);
    let started = Instant::now();
    let mut held = Vec::with_capacity(ctx.idle_conns);
    let mut pending = tokio::task::JoinSet::new();
    let mut failures = 0usize;
    let mut first_error = None;
    for _ in 0..ctx.idle_conns {
        if pending.len() >= 64
            && let Some(done) = pending.join_next().await
        {
            match done {
                Ok(Ok(stream)) => held.push(stream),
                Ok(Err(e)) => {
                    failures += 1;
                    first_error.get_or_insert(e);
                }
                Err(_) => failures += 1,
            }
        }
        let opening = open();
        pending.spawn(async move {
            tokio::time::timeout(Duration::from_secs(10), opening)
                .await
                .map_err(|_| "held connection not proven within 10 s".to_string())?
        });
    }
    while let Some(done) = pending.join_next().await {
        match done {
            Ok(Ok(stream)) => held.push(stream),
            Ok(Err(e)) => {
                failures += 1;
                first_error.get_or_insert(e);
            }
            Err(_) => failures += 1,
        }
    }
    let open_ms = started.elapsed().as_secs_f64() * 1e3;
    if held.is_empty() {
        return Err(format!(
            "no connection opened: {}",
            first_error.unwrap_or_default()
        ));
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let loaded = probe::memory(pid, true).ok_or("read core memory")?;
    let server_loaded = ctx.pids.server.and_then(|p| probe::memory(p, true));
    let fds_loaded = probe::open_fds(pid);
    let count = held.len() as f64;
    for item in held.drain(..) {
        close(item);
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after = probe::memory(pid, true).ok_or("read core memory")?;
    let mut m = Metrics::new();
    let kib = |a: u64, b: u64| (a as f64 - b as f64) / 1024.0 / count;
    m.insert(
        "kib_per_conn".into(),
        kib(loaded.footprint, before.footprint),
    );
    m.insert(
        "retained_kib_per_conn".into(),
        kib(after.footprint, before.footprint),
    );
    m.insert("open_ms".into(), open_ms);
    m.insert("failed".into(), failures as f64);
    m.insert("threads_loaded".into(), loaded.threads as f64);
    if let (Some(b), Some(l)) = (server_before, server_loaded) {
        m.insert("server_kib_per_conn".into(), kib(l.footprint, b.footprint));
    }
    if let (Some(b), Some(l)) = (fds_before, fds_loaded) {
        m.insert("fds_per_conn".into(), (l as f64 - b as f64) / count);
    }
    Ok(m)
}

/// After `ready`: settle, then read what an idle core holds.
pub async fn settled(pid: u32, ready: Duration, settle: Duration) -> Metrics {
    let ready_usage = probe::usage(pid);
    tokio::time::sleep(settle).await;
    let mut m = Metrics::new();
    m.insert("ready_ms".into(), ready.as_secs_f64() * 1e3);
    if let Some(usage) = ready_usage {
        m.insert("ready_cpu_ms".into(), usage.cpu_ns() as f64 / 1e6);
    }
    if let Some(mem) = probe::memory(pid, true) {
        m.insert("footprint_mib".into(), mem.footprint as f64 / MIB);
        m.insert("rss_mib".into(), mem.rss as f64 / MIB);
        m.insert("peak_mib".into(), mem.peak as f64 / MIB);
        m.insert("threads".into(), mem.threads as f64);
    }
    if let Some(fds) = probe::open_fds(pid) {
        m.insert("fds".into(), fds as f64);
    }
    if let Some(usage) = probe::usage(pid) {
        m.insert("startup_cpu_ms".into(), usage.cpu_ns() as f64 / 1e6);
    }
    m
}
