use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::pin;
use std::time::Duration;

use concord_common::{
    Address, BoxStream, ConnStep, CoreError, DialCx, IpVersion, LookupIps, SockOpts, no_retry,
};
use concord_platform::is_local_exhaustion;
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout_at};

/// How long the preferred family has to win before the other family's connection is used.
const FALLBACK_AFTER: Duration = Duration::from_millis(300);

fn is_fatal(err: &io::Error) -> bool {
    no_retry(err) || matches!(CoreError::of(err), Some(CoreError::FdPressure))
}

fn join_errors(errors: Vec<io::Error>) -> io::Error {
    if let Some(index) = errors
        .iter()
        .position(|err| CoreError::of(err).is_some() || is_local_exhaustion(err))
    {
        return errors
            .into_iter()
            .nth(index)
            .unwrap_or_else(|| io::Error::other("dial failed"));
    }
    let kind = errors
        .first()
        .map_or(io::ErrorKind::NotFound, io::Error::kind);
    match errors.len() {
        0 => io::Error::new(kind, "no address to dial"),
        1 => errors
            .into_iter()
            .next()
            .unwrap_or_else(|| io::Error::from(kind)),
        _ => {
            let joined: Vec<String> = errors.iter().map(ToString::to_string).collect();
            io::Error::new(kind, joined.join("; "))
        }
    }
}

async fn serial<T, C, F>(connect: &C, ips: &[IpAddr], port: u16) -> io::Result<T>
where
    C: Fn(SocketAddr) -> F,
    F: Future<Output = io::Result<T>>,
{
    let mut errors = Vec::new();
    for ip in ips {
        match connect(SocketAddr::new(*ip, port)).await {
            Ok(done) => return Ok(done),
            Err(err) if is_fatal(&err) => return Err(err),
            Err(err) => errors.push(err),
        }
    }
    Err(join_errors(errors))
}

async fn parallel<T, C, F>(connect: &C, ips: &[IpAddr], port: u16) -> io::Result<T>
where
    C: Fn(SocketAddr) -> F,
    F: Future<Output = io::Result<T>>,
{
    let mut attempts: FuturesUnordered<_> = ips
        .iter()
        .map(|ip| connect(SocketAddr::new(*ip, port)))
        .collect();
    let mut errors = Vec::new();
    while let Some(result) = attempts.next().await {
        match result {
            Ok(done) => return Ok(done),
            Err(err) if is_fatal(&err) => return Err(err),
            Err(err) => errors.push(err),
        }
    }
    Err(join_errors(errors))
}

async fn group<T, C, F>(connect: &C, ips: &[IpAddr], port: u16, concurrent: bool) -> io::Result<T>
where
    C: Fn(SocketAddr) -> F,
    F: Future<Output = io::Result<T>>,
{
    if concurrent && ips.len() > 1 {
        parallel(connect, ips, port).await
    } else {
        serial(connect, ips, port).await
    }
}

/// Both families start together; the preferred one wins if it connects within
/// `FALLBACK_AFTER`, and otherwise whichever connects first is used.
async fn dual_stack<T, C, F>(
    connect: &C,
    primary: &[IpAddr],
    secondary: &[IpAddr],
    port: u16,
    concurrent: bool,
) -> io::Result<T>
where
    C: Fn(SocketAddr) -> F,
    F: Future<Output = io::Result<T>>,
{
    let mut first = pin!(group(connect, primary, port, concurrent));
    let mut second = pin!(group(connect, secondary, port, concurrent));
    let mut timer = pin!(sleep(FALLBACK_AFTER));
    let (mut first_done, mut second_done, mut timer_done) = (false, false, false);
    let (mut first_err, mut second_err) = (None, None);
    let mut fallback: Option<T> = None;
    loop {
        tokio::select! {
            result = &mut first, if !first_done => {
                first_done = true;
                match result {
                    Ok(done) => return Ok(done),
                    Err(err) => {
                        first_err = Some(err);
                        if let Some(done) = fallback.take() {
                            return Ok(done);
                        }
                    }
                }
            }
            result = &mut second, if !second_done => {
                second_done = true;
                match result {
                    Ok(done) if timer_done || first_done => return Ok(done),
                    Ok(done) => fallback = Some(done),
                    Err(err) => second_err = Some(err),
                }
            }
            () = &mut timer, if !timer_done => {
                timer_done = true;
                if let Some(done) = fallback.take() {
                    return Ok(done);
                }
            }
        }
        if first_done && second_done {
            return Err(join_errors(
                first_err.into_iter().chain(second_err).collect(),
            ));
        }
    }
}

pub(crate) struct Resolved {
    pub(crate) v4: Vec<IpAddr>,
    pub(crate) v6: Vec<IpAddr>,
}

pub(crate) async fn resolve(
    cx: &DialCx<'_>,
    target: &Address,
    version: IpVersion,
) -> io::Result<Resolved> {
    let ipv6_enabled = cx.env.ipv6;
    if version == IpVersion::Ipv6 && !ipv6_enabled {
        return Err(CoreError::Ipv6Disabled.into());
    }
    let found = match target {
        Address::Socket(addr) if addr.is_ipv4() => LookupIps {
            v4: vec![addr.ip()],
            v6: Vec::new(),
        },
        Address::Socket(addr) => LookupIps {
            v4: Vec::new(),
            v6: vec![addr.ip()],
        },
        Address::Domain(host, _) => {
            cx.mark(ConnStep::DnsStart);
            let found = cx.env.resolver.lookup(host, version, cx.initiator).await;
            cx.mark(ConnStep::DnsEnd);
            found?
        }
    };
    arrange(found, target, version, ipv6_enabled)
}

fn arrange(
    found: LookupIps,
    target: &Address,
    version: IpVersion,
    ipv6_enabled: bool,
) -> io::Result<Resolved> {
    let LookupIps { mut v4, mut v6 } = found;
    v6.retain(|ip| match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().is_none_or(|mapped| {
            v4.push(IpAddr::V4(mapped));
            false
        }),
        IpAddr::V4(_) => true,
    });
    match version {
        IpVersion::Ipv4 => v6.clear(),
        IpVersion::Ipv6 => v4.clear(),
        _ => {}
    }
    let had_v6 = !v6.is_empty();
    if !ipv6_enabled {
        v6.clear();
    }
    if v4.is_empty() && v6.is_empty() {
        return Err(if had_v6 {
            CoreError::Ipv6Disabled.into()
        } else {
            CoreError::IpNotFound(target.host_string()).into()
        });
    }
    Ok(Resolved { v4, v6 })
}

/// Resolves `target` and runs `connect` over its addresses as mihomo's dialer does:
/// one family in order (all at once with `tcp-concurrent`), and with both families the
/// preferred one first and the other `FALLBACK_AFTER` later.
pub async fn dial_each<T, C, F>(
    cx: &DialCx<'_>,
    target: &Address,
    version: IpVersion,
    connect: C,
) -> io::Result<T>
where
    C: Fn(SocketAddr) -> F,
    F: Future<Output = io::Result<T>>,
{
    let resolved = resolve(cx, target, version).await?;
    dial_resolved(cx, resolved, target.port(), version, connect).await
}

/// `dial_each` over addresses the caller looked up itself, as mihomo's dialer does
/// when an adapter hands it its own resolver.
pub async fn dial_found<T, C, F>(
    cx: &DialCx<'_>,
    found: LookupIps,
    target: &Address,
    version: IpVersion,
    connect: C,
) -> io::Result<T>
where
    C: Fn(SocketAddr) -> F,
    F: Future<Output = io::Result<T>>,
{
    if version == IpVersion::Ipv6 && !cx.env.ipv6 {
        return Err(CoreError::Ipv6Disabled.into());
    }
    let resolved = arrange(found, target, version, cx.env.ipv6)?;
    dial_resolved(cx, resolved, target.port(), version, connect).await
}

async fn dial_resolved<T, C, F>(
    cx: &DialCx<'_>,
    Resolved { v4, v6 }: Resolved,
    port: u16,
    version: IpVersion,
    connect: C,
) -> io::Result<T>
where
    C: Fn(SocketAddr) -> F,
    F: Future<Output = io::Result<T>>,
{
    let concurrent = cx.env.tcp_concurrent;
    match (v4.is_empty(), v6.is_empty()) {
        (false, true) => group(&connect, &v4, port, concurrent).await,
        (true, _) => group(&connect, &v6, port, concurrent).await,
        (false, false) if version == IpVersion::Dual && concurrent => {
            let all: Vec<IpAddr> = v4.into_iter().chain(v6).collect();
            parallel(&connect, &all, port).await
        }
        (false, false) if version == IpVersion::Ipv6Prefer => {
            dual_stack(&connect, &v6, &v4, port, concurrent).await
        }
        (false, false) => dual_stack(&connect, &v4, &v6, port, concurrent).await,
    }
}

/// Resolves `target` and connects, stopping at `cx.deadline`. There is no retry:
/// a caller that wants another attempt decides that with the error in hand.
pub async fn dial_tcp(
    cx: &DialCx<'_>,
    target: &Address,
    version: IpVersion,
    opts: &SockOpts,
) -> io::Result<TcpStream> {
    let sockets = &cx.env.sockets;
    until_deadline(
        cx,
        target,
        dial_each(cx, target, version, |addr| sockets.connect_tcp(addr, opts)),
    )
    .await
}

/// `dial_tcp` through `SocketFactory::connect_stream`, for a caller that keeps only a
/// `Stream`; a deferred Fast Open handshake is not waited for.
pub async fn dial_stream(
    cx: &DialCx<'_>,
    target: &Address,
    version: IpVersion,
    opts: &SockOpts,
) -> io::Result<BoxStream> {
    let sockets = &cx.env.sockets;
    until_deadline(
        cx,
        target,
        dial_each(cx, target, version, |addr| {
            sockets.connect_stream(addr, opts)
        }),
    )
    .await
}

async fn until_deadline<T>(
    cx: &DialCx<'_>,
    target: &Address,
    work: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    match cx.deadline {
        Some(deadline) => timeout_at(deadline, work).await.unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("dial {target} timed out"),
            ))
        }),
        None => work.await,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use concord_common::{DialEnv, Initiator, SocketFactory};
    use tokio::time::Instant;

    use super::*;

    use crate::Sockets;
    use crate::test_support::{FakePlatform, MapResolver, ScriptedSockets, env};
    use concord_common::sync::lock;

    const MS: fn(u64) -> Duration = Duration::from_millis;

    #[test]
    fn joined_failures_keep_running_out_of_memory() {
        let err = join_errors(vec![
            io::Error::from(io::ErrorKind::TimedOut),
            io::Error::from(io::ErrorKind::OutOfMemory),
        ]);
        assert!(is_local_exhaustion(&err), "{err}");
    }

    fn domain(port: u16) -> Address {
        Address::Domain("example.test".into(), port)
    }

    fn scripted_env(
        sockets: &Arc<ScriptedSockets>,
        v4: &[&str],
        v6: &[&str],
        concurrent: bool,
    ) -> DialEnv {
        env(
            Arc::clone(sockets) as Arc<dyn SocketFactory>,
            MapResolver::with("example.test", v4, v6),
            concurrent,
            true,
        )
    }

    async fn run(
        env: &DialEnv,
        version: IpVersion,
        deadline: Option<Instant>,
    ) -> io::Result<TcpStream> {
        let cx = DialCx::new(env, Initiator::Other, deadline);
        dial_tcp(&cx, &domain(443), version, &SockOpts::default()).await
    }

    fn is_from(stream: &TcpStream, far_end: &TcpStream) -> bool {
        stream.local_addr().unwrap() == far_end.peer_addr().unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn the_preferred_family_wins_when_both_are_ready() {
        let sockets = Arc::new(ScriptedSockets::new());
        let v4_far = sockets.succeed("203.0.113.1", MS(0));
        let _v6_far = sockets.succeed("2001:db8::1", MS(0));
        let env = scripted_env(&sockets, &["203.0.113.1"], &["2001:db8::1"], false);

        let stream = run(&env, IpVersion::Dual, None).await.unwrap();
        assert!(is_from(&stream, &v4_far));
    }

    #[tokio::test(start_paused = true)]
    async fn the_other_family_is_used_after_the_stagger() {
        let sockets = Arc::new(ScriptedSockets::new());
        let _v4_far = sockets.succeed("203.0.113.1", MS(800));
        let v6_far = sockets.succeed("2001:db8::1", MS(10));
        let env = scripted_env(&sockets, &["203.0.113.1"], &["2001:db8::1"], false);

        let started = Instant::now();
        let stream = run(&env, IpVersion::Dual, None).await.unwrap();
        assert!(is_from(&stream, &v6_far));
        assert_eq!(started.elapsed(), FALLBACK_AFTER);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_primary_hands_over_at_once() {
        let sockets = Arc::new(ScriptedSockets::new());
        sockets.fail("203.0.113.1", MS(20));
        let v6_far = sockets.succeed("2001:db8::1", MS(5));
        let env = scripted_env(&sockets, &["203.0.113.1"], &["2001:db8::1"], false);

        let started = Instant::now();
        let stream = run(&env, IpVersion::Dual, None).await.unwrap();
        assert!(is_from(&stream, &v6_far));
        assert_eq!(started.elapsed(), MS(20));
    }

    #[tokio::test(start_paused = true)]
    async fn ipv6_prefer_swaps_the_roles() {
        let sockets = Arc::new(ScriptedSockets::new());
        let _v4_far = sockets.succeed("203.0.113.1", MS(0));
        let v6_far = sockets.succeed("2001:db8::1", MS(100));
        let env = scripted_env(&sockets, &["203.0.113.1"], &["2001:db8::1"], false);

        let stream = run(&env, IpVersion::Ipv6Prefer, None).await.unwrap();
        assert!(is_from(&stream, &v6_far));
    }

    #[tokio::test(start_paused = true)]
    async fn serial_dialing_tries_addresses_in_order() {
        let sockets = Arc::new(ScriptedSockets::new());
        sockets.fail("203.0.113.1", MS(10));
        sockets.fail("203.0.113.2", MS(10));
        let far = sockets.succeed("203.0.113.3", MS(10));
        let env = scripted_env(
            &sockets,
            &["203.0.113.1", "203.0.113.2", "203.0.113.3"],
            &[],
            false,
        );

        let started = Instant::now();
        let stream = run(&env, IpVersion::Dual, None).await.unwrap();
        assert!(is_from(&stream, &far));
        assert_eq!(started.elapsed(), MS(30));
        assert_eq!(lock(&sockets.attempts).len(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_dialing_races_every_address() {
        let sockets = Arc::new(ScriptedSockets::new());
        let _slow = sockets.succeed("203.0.113.1", MS(500));
        sockets.fail("203.0.113.2", MS(200));
        let fast = sockets.succeed("203.0.113.3", MS(50));
        let env = scripted_env(
            &sockets,
            &["203.0.113.1", "203.0.113.2", "203.0.113.3"],
            &[],
            true,
        );

        let started = Instant::now();
        let stream = run(&env, IpVersion::Dual, None).await.unwrap();
        assert!(is_from(&stream, &fast));
        assert_eq!(started.elapsed(), MS(50));
        assert_eq!(lock(&sockets.attempts).len(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_dial_with_nothing_reachable_reports_the_failure() {
        let sockets = Arc::new(ScriptedSockets::new());
        sockets.fail("203.0.113.1", MS(5));
        sockets.fail("2001:db8::1", MS(5));
        let env = scripted_env(&sockets, &["203.0.113.1"], &["2001:db8::1"], false);

        let err = run(&env, IpVersion::Dual, None).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[tokio::test(start_paused = true)]
    async fn the_deadline_cuts_a_slow_connection() {
        let sockets = Arc::new(ScriptedSockets::new());
        let _far = sockets.succeed("203.0.113.1", Duration::from_secs(60));
        let env = scripted_env(&sockets, &["203.0.113.1"], &[], false);

        let started = Instant::now();
        let deadline = Some(started + Duration::from_secs(5));
        let err = run(&env, IpVersion::Dual, deadline).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_ipv6_filters_addresses_and_rejects_v6_only_targets() {
        let sockets = Arc::new(ScriptedSockets::new());
        let far = sockets.succeed("203.0.113.1", MS(0));
        let mixed = env(
            Arc::clone(&sockets) as Arc<dyn SocketFactory>,
            MapResolver::with("example.test", &["203.0.113.1"], &["2001:db8::1"]),
            false,
            false,
        );
        let stream = run(&mixed, IpVersion::Dual, None).await.unwrap();
        assert!(is_from(&stream, &far));
        assert_eq!(
            *lock(&sockets.attempts),
            vec!["203.0.113.1".parse::<IpAddr>().unwrap()]
        );

        let only_v6 = env(
            Arc::clone(&sockets) as Arc<dyn SocketFactory>,
            MapResolver::with("example.test", &[], &["2001:db8::1"]),
            false,
            false,
        );
        let err = run(&only_v6, IpVersion::Dual, None).await.unwrap_err();
        assert_eq!(CoreError::of(&err), Some(&CoreError::Ipv6Disabled));
        let err = run(&mixed, IpVersion::Ipv6, None).await.unwrap_err();
        assert_eq!(CoreError::of(&err), Some(&CoreError::Ipv6Disabled));
    }

    #[tokio::test(start_paused = true)]
    async fn an_empty_answer_is_ip_not_found_and_a_literal_skips_the_resolver() {
        let sockets = Arc::new(ScriptedSockets::new());
        let resolver = MapResolver::with("example.test", &[], &[]);
        let env = env(
            Arc::clone(&sockets) as Arc<dyn SocketFactory>,
            resolver.clone(),
            false,
            true,
        );

        let err = run(&env, IpVersion::Dual, None).await.unwrap_err();
        assert_eq!(
            CoreError::of(&err),
            Some(&CoreError::IpNotFound("example.test".into()))
        );
        assert!(concord_common::no_retry(&err));

        let far = sockets.succeed("203.0.113.9", MS(0));
        let cx = DialCx::new(&env, Initiator::Other, None);
        let literal = Address::new("203.0.113.9", 443);
        let before = resolver.lookups.load(std::sync::atomic::Ordering::Relaxed);
        let stream = dial_tcp(&cx, &literal, IpVersion::Dual, &SockOpts::default())
            .await
            .unwrap();
        assert!(is_from(&stream, &far));
        assert_eq!(
            resolver.lookups.load(std::sync::atomic::Ordering::Relaxed),
            before
        );
    }

    #[tokio::test]
    async fn a_real_connection_goes_through_the_socket_factory() {
        let platform = Arc::new(FakePlatform::default());
        let sockets = Arc::new(Sockets::new(
            platform.clone() as Arc<dyn concord_platform::Platform>
        ));
        let (listener, addr) = crate::test_support::loopback_listener().await;
        let env = env(
            sockets,
            MapResolver::with("example.test", &["127.0.0.1"], &[]),
            false,
            true,
        );

        let cx = DialCx::new(&env, Initiator::Direct, None);
        let target = Address::Domain("example.test".into(), addr.port());
        let opts = SockOpts::default();
        let (dialed, accepted) = tokio::join!(
            dial_tcp(&cx, &target, IpVersion::Dual, &opts),
            listener.accept()
        );
        assert_eq!(dialed.unwrap().peer_addr().unwrap(), addr);
        accepted.unwrap();
        assert_eq!(lock(&platform.protected).len(), 1);
    }
}
