use std::time::Duration;

use super::*;
use crate::testing::capture_errors;

async fn settle_runtime() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn dropping_a_tunnel_emits_no_tun_errors() {
    let server = server(PublicKey::from(&secret(2))).await;
    let tracked = crate::testing::Tracked::new();
    let outbound = client_with(
        "127.0.0.1",
        server.port,
        &server.public,
        json!({}),
        tracked.tasks.clone(),
    );
    echo(
        &*outbound,
        Address::new(&SERVER_TUNNEL_IP.to_string(), 7),
        16,
    )
    .await;

    let (errors, _guard) = capture_errors();
    drop(outbound);
    assert!(tracked.ended_within(Duration::from_secs(5)).await);
    settle_runtime().await;

    let recorded = errors.lock().unwrap().clone();
    assert!(
        recorded.is_empty(),
        "dropping a tunnel logged errors: {recorded:?}"
    );
    drop(_guard);
    drop(server);
}

#[tokio::test]
async fn stopping_the_tracker_before_dropping_a_tunnel_emits_no_tun_errors() {
    let server = server(PublicKey::from(&secret(2))).await;
    let tracked = crate::testing::Tracked::new();
    let outbound = client_with(
        "127.0.0.1",
        server.port,
        &server.public,
        json!({}),
        tracked.tasks.clone(),
    );
    echo(
        &*outbound,
        Address::new(&SERVER_TUNNEL_IP.to_string(), 7),
        16,
    )
    .await;

    let (errors, _guard) = capture_errors();
    tracked.stop();
    settle_runtime().await;
    drop(outbound);
    assert!(tracked.ended_within(Duration::from_secs(5)).await);
    settle_runtime().await;

    let recorded = errors.lock().unwrap().clone();
    assert!(
        recorded.is_empty(),
        "stopping the tracker before dropping a tunnel logged errors: {recorded:?}"
    );
    drop(_guard);
    drop(server);
}

#[tokio::test(start_paused = true)]
async fn retiring_an_idle_tunnel_emits_no_tun_errors() {
    let server = server(PublicKey::from(&secret(2))).await;
    let tracked = crate::testing::Tracked::new();
    let outbound = client_with(
        "127.0.0.1",
        server.port,
        &server.public,
        json!({}),
        tracked.tasks.clone(),
    );
    echo(
        &*outbound,
        Address::new(&SERVER_TUNNEL_IP.to_string(), 7),
        16,
    )
    .await;
    assert!(outbound.shared.current().is_some());

    let (errors, _guard) = capture_errors();
    tokio::time::sleep(Duration::from_secs(200)).await;
    assert!(outbound.shared.current().is_none());
    assert!(tracked.ended_within(Duration::from_secs(5)).await);
    settle_runtime().await;

    let recorded = errors.lock().unwrap().clone();
    assert!(
        recorded.is_empty(),
        "retiring an idle tunnel logged errors: {recorded:?}"
    );
    drop(_guard);
    drop(server);
}

#[tokio::test]
async fn unexpected_channel_close_while_tunnel_is_active_still_logs_tun_errors() {
    let server = server(PublicKey::from(&secret(2))).await;
    let tracked = crate::testing::Tracked::new();
    let outbound = client_with(
        "127.0.0.1",
        server.port,
        &server.public,
        json!({}),
        tracked.tasks.clone(),
    );
    echo(
        &*outbound,
        Address::new(&SERVER_TUNNEL_IP.to_string(), 7),
        16,
    )
    .await;
    let tunnel = outbound.shared.current().unwrap();

    let (errors, _guard) = capture_errors();
    tunnel.abort_driver();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let recorded = errors.lock().unwrap();
        let has_deleted = recorded
            .iter()
            .any(|msg| msg.contains("TUN device was deleted"));
        let has_unexpected = recorded
            .iter()
            .any(|msg| msg.contains("Unexpected error on tun interface"));
        if has_deleted && has_unexpected {
            break;
        }
        drop(recorded);
        assert!(
            tokio::time::Instant::now() < deadline,
            "expected both TUN errors on unexpected channel close, saw: {:?}",
            *errors.lock().unwrap()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    drop(_guard);
    drop(tunnel);
    drop(outbound);
    assert!(tracked.ended_within(Duration::from_secs(5)).await);
    drop(server);
}
