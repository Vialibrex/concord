use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::process::Child;

use crate::cases::{Case, Spec};
use crate::isolate::{self, Placement};

const PEER_PORT: u16 = 41641;

/// The `tailscale` case: headscale is the control server and a kernel-TUN tailscaled peer beside
/// the origin advertises the origin's address as a subnet route, so each core reaches the origin
/// through the tailnet. Every core is its own ephemeral node, logged in with one reusable key.
pub fn case(spec: Spec, host: &str, port: u16) -> Option<Case> {
    if spec.name != "tailscale" {
        return None;
    }
    Some(Case {
        tailscale: true,
        proxy: Some(json!({
            "name": spec.name, "type": "tailscale", "control-url": format!("http://{host}:{port}"),
            "auth-key": "", "ephemeral": true, "udp": true, "accept-routes": true,
        })),
        ..Case::bare(spec)
    })
}

fn control_url(case: &Case) -> Option<String> {
    case.proxy
        .as_ref()?
        .get("control-url")?
        .as_str()
        .map(str::to_string)
}

async fn run(tool: &Path, args: &[&str], placement: &Placement) -> std::io::Result<String> {
    let output = isolate::command(tool, placement)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "{} {}: {}",
            tool.display(),
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn json_of(text: &str) -> std::io::Result<Value> {
    serde_json::from_str(text).map_err(std::io::Error::other)
}

fn spawn_logged(
    program: &Path,
    args: &[String],
    log: &Path,
    placement: &Placement,
) -> std::io::Result<Child> {
    let file = std::fs::File::create(log)?;
    let mut command = isolate::command(program, placement);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(file.try_clone()?)
        .stderr(file);
    isolate::spawn(&mut command, placement)
}

async fn until(what: &str, mut check: impl AsyncFnMut() -> bool) -> std::io::Result<()> {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(20) {
        if check().await {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err(std::io::Error::other(format!(
        "{what} did not come up in 20 s"
    )))
}

fn headscale_config(dir: &Path, url: &str, ip: IpAddr) -> String {
    let listen = url.trim_start_matches("http://");
    let path = |name: &str| dir.join(name).display().to_string();
    format!(
        "server_url: {url}\nlisten_addr: {listen}\nmetrics_listen_addr: 127.0.0.1:0\n\
         grpc_listen_addr: 127.0.0.1:0\nnoise:\n  private_key_path: {}\n\
         prefixes:\n  v4: 100.64.0.0/10\n  v6: fd7a:115c:a1e0::/48\n  allocation: sequential\n\
         derp:\n  server:\n    enabled: true\n    region_id: 999\n    region_code: bench\n\
         \x20   region_name: bench\n    stun_listen_addr: {ip}:3478\n    private_key_path: {}\n\
         \x20   automatically_add_embedded_derp_region: true\n    ipv4: {ip}\n  urls: []\n  paths: []\n\
         \x20 auto_update_enabled: false\ndatabase:\n  type: sqlite\n  sqlite:\n    path: {}\n\
         dns:\n  magic_dns: true\n  base_domain: bench.test\n  override_local_dns: false\n\
         \x20 nameservers:\n    global: []\nunix_socket: {}\nunix_socket_permission: \"0770\"\n\
         log:\n  level: info\n",
        path("noise.key"),
        path("derp.key"),
        path("db.sqlite"),
        path("headscale.sock"),
    )
}

/// Starts headscale and the peer for each tailscale case, logs the peer in with its route
/// approved, and writes the cores' auth key into the case. The peer is first in the list, so
/// its pid is the case's server pid.
pub async fn start(
    cases: &mut [Case],
    ip: IpAddr,
    tools: Option<&Path>,
    dir: &Path,
    placement: &Placement,
) -> std::io::Result<Vec<(String, Child)>> {
    let mut children = Vec::new();
    for case in cases.iter_mut().filter(|case| case.tailscale) {
        if ip.is_loopback() {
            return Err(fail(
                "tailscale needs --netem: the peer routes the far origin",
            ));
        }
        let tools = tools.ok_or_else(|| {
            fail("tailscale needs --tailscale (or CONCORD_TAILSCALE): a directory with headscale, tailscale and tailscaled")
        })?;
        let url = control_url(case).ok_or_else(|| fail("tailscale case without control-url"))?;
        let home = dir.join(format!("server/{}", case.name()));
        std::fs::create_dir_all(&home)?;
        let config = home.join("config.yaml");
        std::fs::write(&config, headscale_config(&home, &url, ip))?;
        let hs = Headscale {
            bin: tools.join("headscale"),
            config,
            placement,
        };
        let log = |what: &str| dir.join(format!("logs/{}-{what}.log", case.name()));
        let control = hs.serve(&url, &log("headscale")).await?;
        let key = hs.auth_key().await?;
        let peer = peer_up(tools, &home, &url, &key, ip, &log("tailscaled"), placement).await?;
        hs.approve(ip).await?;
        if let Some(proxy) = case.proxy.as_mut() {
            proxy["auth-key"] = json!(key);
        }
        children.push((case.name().to_string(), peer));
        children.push((case.name().to_string(), control));
    }
    Ok(children)
}

fn fail(why: &str) -> std::io::Error {
    std::io::Error::other(why.to_string())
}

struct Headscale<'a> {
    bin: PathBuf,
    config: PathBuf,
    placement: &'a Placement,
}

impl Headscale<'_> {
    async fn run(&self, rest: &[&str]) -> std::io::Result<String> {
        let config = self.config.to_str().unwrap_or_default();
        let args: Vec<&str> = ["-c", config].iter().chain(rest).copied().collect();
        run(&self.bin, &args, self.placement).await
    }

    async fn serve(&self, url: &str, log: &Path) -> std::io::Result<Child> {
        let config = self.config.to_str().unwrap_or_default().to_string();
        let args = ["-c".to_string(), config, "serve".to_string()];
        let control = spawn_logged(&self.bin, &args, log, self.placement)?;
        let health = format!("{url}/health");
        until("headscale", async || {
            run(
                Path::new("curl"),
                &["-sf", "-o", "/dev/null", &health],
                self.placement,
            )
            .await
            .is_ok()
        })
        .await?;
        Ok(control)
    }

    async fn auth_key(&self) -> std::io::Result<String> {
        self.run(&["users", "create", "bench"]).await?;
        let users = json_of(&self.run(&["users", "list", "-o", "json"]).await?)?;
        let user = users
            .as_array()
            .and_then(|all| all.iter().find(|u| u["name"] == "bench"))
            .and_then(|u| u["id"].as_u64())
            .ok_or_else(|| fail("headscale has no bench user"))?
            .to_string();
        let created = self
            .run(&[
                "preauthkeys",
                "create",
                "-u",
                &user,
                "--reusable",
                "--expiration",
                "4h",
                "-o",
                "json",
            ])
            .await?;
        json_of(&created)?["key"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| fail("headscale gave no preauth key"))
    }

    async fn approve(&self, ip: IpAddr) -> std::io::Result<()> {
        let nodes = json_of(&self.run(&["nodes", "list", "-o", "json"]).await?)?;
        let node = nodes
            .as_array()
            .and_then(|all| {
                all.iter().find(|n| {
                    n["name"]
                        .as_str()
                        .is_some_and(|s| s.starts_with("bench-peer"))
                })
            })
            .and_then(|n| n["id"].as_u64())
            .ok_or_else(|| fail("headscale does not list the peer"))?
            .to_string();
        let route = format!("{ip}/32");
        self.run(&["nodes", "approve-routes", "-i", &node, "-r", &route])
            .await?;
        Ok(())
    }
}

async fn peer_up(
    tools: &Path,
    home: &Path,
    url: &str,
    key: &str,
    ip: IpAddr,
    log: &Path,
    placement: &Placement,
) -> std::io::Result<Child> {
    let socket = home.join("peer.sock");
    let socket_arg = format!("--socket={}", socket.display());
    let peer = spawn_logged(
        &tools.join("tailscaled"),
        &[
            format!("--state={}", home.join("peer.state").display()),
            socket_arg.clone(),
            "--tun=tsbench0".to_string(),
            format!("--port={PEER_PORT}"),
            format!("--statedir={}", home.join("peerdir").display()),
        ],
        log,
        placement,
    )?;
    until("tailscaled", async || socket.exists()).await?;
    let route = format!("--advertise-routes={ip}/32");
    run(
        &tools.join("tailscale"),
        &[
            &socket_arg,
            "up",
            &format!("--login-server={url}"),
            &format!("--authkey={key}"),
            "--hostname=bench-peer",
            &route,
            "--accept-dns=false",
        ],
        placement,
    )
    .await?;
    Ok(peer)
}
