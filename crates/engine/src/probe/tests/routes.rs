use concord_common::sync::lock;

use crate::probe::RouteHit;
use crate::probe::testing::{FakeEnv, exit_name};

fn hit(host: &str, proxy: &str, exit: &str) -> RouteHit {
    RouteHit {
        host: host.into(),
        proxy: proxy.into(),
        exit: exit.into(),
    }
}

#[tokio::test]
async fn every_route_with_hits_holds_while_the_exits_do() {
    let env = FakeEnv::new(&["node-a"]);
    env.set_stamp(3, 9);
    let proxied = hit("example.com:443", "node-a", &exit_name("node-a"));
    let direct = hit("example.org:443", "", &exit_name("DIRECT"));
    let routes = vec![
        vec![proxied.clone()],
        vec![direct.clone()],
        vec![proxied.clone(), direct.clone()],
        vec![],
    ];
    let prober = env.prober();

    let (stamp, held) = prober.check_routes(&routes).await;

    assert_eq!((stamp.epoch, stamp.version), (3, 9));
    assert_eq!(held, [true, true, true, false]);

    lock(&env.known).clear();
    let (_, held) = prober.check_routes(&routes).await;
    assert_eq!(held, [false, true, false, false]);
}

#[tokio::test]
async fn a_missing_proxy_stays_missing() {
    let env = FakeEnv::new(&["node-a"]);
    let missing = vec![vec![hit("", "gone", "")]];
    let prober = env.prober();

    assert_eq!(prober.check_routes(&missing).await.1, [true]);

    lock(&env.known).push("gone".into());
    assert_eq!(prober.check_routes(&missing).await.1, [false]);
}

#[tokio::test]
async fn a_hit_with_the_wrong_exit_drops_the_whole_route() {
    let env = FakeEnv::new(&["node-a"]);
    let good = hit("a:1", "node-a", &exit_name("node-a"));
    let stale = hit("b:1", "node-a", "\"node-b\" Test node-b.example:1");

    let (_, held) = env
        .prober()
        .check_routes(&[vec![good.clone(), stale], vec![good]])
        .await;

    assert_eq!(held, [false, true]);
}
