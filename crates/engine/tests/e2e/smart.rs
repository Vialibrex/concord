use super::*;

/// A SOCKS5 server that holds its answer to the n-th CONNECT for `target` for `delays[n]` (the last one for every
/// later connection), then relays like `upstream_socks`. Other targets, such as the group's tests, are not held.
async fn slow_socks(target: SocketAddr, delays: Vec<Duration>) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let wanted = target.to_string();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let log = log.clone();
            let delays = delays.clone();
            let wanted = wanted.clone();
            tokio::spawn(async move {
                let mut greeting = [0u8; 2];
                client.read_exact(&mut greeting).await.ok()?;
                let mut methods = vec![0u8; usize::from(greeting[1])];
                client.read_exact(&mut methods).await.ok()?;
                client.write_all(&[5, 0]).await.ok()?;
                let target = read_socks_target(&mut client).await?;
                let earlier = {
                    let mut log = lock(&log);
                    let earlier = log.iter().filter(|seen| **seen == wanted).count();
                    log.push(target.clone());
                    earlier
                };
                if target == wanted {
                    let delay = delays.get(earlier).or(delays.last()).copied();
                    tokio::time::sleep(delay.unwrap_or_default()).await;
                }
                let mut remote = TcpStream::connect(&target).await.ok()?;
                client
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .ok()?;
                tokio::io::copy_bidirectional(&mut client, &mut remote)
                    .await
                    .ok()
            });
        }
    });
    (port, seen)
}

/// A port nothing listens on: a dial to it is refused at once.
fn closed_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Every test of the group fails, so no member has a delay and the group's first member is the default.
fn smart_group(members: &str) -> String {
    format!(
        "proxy-groups:\n  - {{name: s, type: smart, proxies: [{members}], url: 'http://127.0.0.1:{}/', interval: 0}}\nrules:\n  - MATCH,s\n",
        closed_port()
    )
}

fn socks(name: &str, port: u16) -> String {
    format!("  - {{name: {name}, type: socks5, server: 127.0.0.1, port: {port}}}\n")
}

fn chain_of(rig: &Rig) -> Vec<String> {
    rig.engine.connections()[0]
        .chains
        .iter()
        .map(ToString::to_string)
        .collect()
}

/// How many flows to `target` a SOCKS stub carried; the group's tests through it are left out.
fn carried(seen: &Mutex<Vec<String>>, target: SocketAddr) -> usize {
    let target = target.to_string();
    lock(seen).iter().filter(|seen| **seen == target).count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_smart_group_redials_its_next_member_when_the_first_refuses() {
    let echo = tcp_echo().await;
    let (up, seen) = upstream_socks().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n{}{}{}",
        socks("dead", closed_port()),
        socks("up", up),
        smart_group("dead, up")
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;
    assert_eq!(carried(&seen, echo), 1);
    assert!(eventually(|| rig.engine.connection_count() == 1).await);
    assert_eq!(chain_of(&rig), vec!["up", "s"]);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_last_member_left_gets_the_whole_dial_time() {
    let echo = tcp_echo().await;
    let (slow, seen) = slow_socks(echo, vec![Duration::ZERO, Duration::from_millis(1500)]).await;
    let rig = Rig::new();
    let config = format!("proxies:\n{}{}", socks("slow", slow), smart_group("slow"));
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    let mut first = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut first).await;
    drop(first);
    let mut second = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut second).await;
    assert_eq!(
        carried(&seen, echo),
        2,
        "the slow answer must not be cut short"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_slower_than_its_budget_gives_way_to_the_next() {
    let echo = tcp_echo().await;
    let (slow, slow_seen) =
        slow_socks(echo, vec![Duration::ZERO, Duration::from_millis(2500)]).await;
    let (up, up_seen) = upstream_socks().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n{}{}{}",
        socks("slow", slow),
        socks("up", up),
        smart_group("slow, up")
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    let mut first = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut first).await;
    drop(first);
    assert_eq!(carried(&slow_seen, echo), 1);
    let started = std::time::Instant::now();
    let mut second = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut second).await;
    assert_eq!(carried(&up_seen, echo), 1);
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "the redial waited for the slow member: {:?}",
        started.elapsed()
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pinned_smart_group_does_not_redial_another_member() {
    let echo = tcp_echo().await;
    let (up, seen) = upstream_socks().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n{}{}{}",
        socks("up", up),
        socks("dead", closed_port()),
        smart_group("up, dead")
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    rig.engine.select("s", "dead").await.unwrap();
    assert_eq!(rig.selected("s").as_deref(), Some("dead"));
    assert!(refused(rig.mixed, echo).await);
    assert_eq!(carried(&seen, echo), 0, "the flow left the pinned member");
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_network_change_tests_every_member_of_a_smart_group() {
    let (server, hits) = http_server(HashMap::from([("/ok", "ok".to_string())])).await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: a, type: direct}}\n  - {{name: b, type: direct}}\nproxy-groups:\n  - {{name: s, type: smart, proxies: [a, b], url: 'http://{server}/ok', interval: 300, lazy: false}}\nrules:\n  - MATCH,s\n"
    );
    rig.apply(&config).await.unwrap();
    assert!(eventually(|| hits.load(Ordering::SeqCst) >= 2).await);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let before = hits.load(Ordering::SeqCst);
    rig.engine.network_changed();
    assert!(
        eventually(|| hits.load(Ordering::SeqCst) >= before + 2).await,
        "hits stayed at {}",
        hits.load(Ordering::SeqCst)
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_member_is_not_cut_short_for_an_ejected_one() {
    let echo = tcp_echo().await;
    let (slow, seen) = slow_socks(echo, vec![Duration::ZERO, Duration::from_millis(1500)]).await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n{}{}proxy-groups:\n  - {{name: s, type: smart, proxies: [dead, slow], url: 'http://127.0.0.1:{}/', interval: 0, max-failed-times: 1}}\nrules:\n  - MATCH,s\n",
        socks("dead", closed_port()),
        socks("slow", slow),
        closed_port()
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    let mut first = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut first).await;
    drop(first);
    assert_eq!(carried(&seen, echo), 1);
    let mut second = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut second).await;
    assert_eq!(
        carried(&seen, echo),
        2,
        "each flow connected once through the slow member"
    );
    rig.engine.shutdown().await;
}
