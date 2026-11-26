#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests assert on fixed shapes"
)]

use std::time::{Duration, Instant};

use concord_config::proxy::OpenVpnOpts;
use gotatun::packet::PacketBufPool;

use super::config::{Config, static_key, tls_crypt_v2};
use super::data::{Cipher, DataKey, Keys};
use super::keys::{Digest, KeyMaterial, options_string, parse_server, peer_info};
use super::push::{Inbox, Message, PushReply};
use super::reliable::Reliable;
use super::tunnel::{Opened, keepalive_timers, lzo_prefix, open_data};
use super::wire::{ACK, CONTROL, ControlPacket, PING, SessionId, next_key_id};
use super::wrap::{Replay, Wrap};

mod vectors;

const CLIENT: SessionId = *b"client01";
const SERVER: SessionId = *b"server01";

fn ca() -> String {
    rcgen::generate_simple_self_signed(vec!["openvpn".to_string()])
        .unwrap()
        .cert
        .pem()
}

fn opts() -> OpenVpnOpts {
    OpenVpnOpts {
        server: "127.0.0.1".into(),
        port: 1194,
        cipher: "AES-128-GCM".into(),
        auth: "SHA256".into(),
        ca: ca(),
        username: "u".into(),
        ..OpenVpnOpts::default()
    }
}

fn config(edit: impl FnOnce(&mut OpenVpnOpts)) -> Config {
    let mut opts = opts();
    edit(&mut opts);
    Config::new(&opts).unwrap()
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_string()).collect()
}

fn server_packet(op: u8, message_id: u32, acks: Vec<u32>) -> ControlPacket {
    ControlPacket {
        op,
        session: SERVER,
        acks,
        ack_session: CLIENT,
        message_id,
        payload: vec![message_id as u8],
        ..ControlPacket::default()
    }
}

fn reliable() -> Reliable {
    let mut reliable = Reliable::new(CLIENT, true);
    reliable.remote = Some(SERVER);
    reliable
}

#[test]
fn reliable_delivers_in_order_and_holds_early_messages() {
    let mut reliable = reliable();
    assert!(
        reliable
            .receive(server_packet(CONTROL, 1, vec![]))
            .is_empty()
    );
    assert!(
        reliable
            .receive(server_packet(CONTROL, 2, vec![]))
            .is_empty()
    );
    let delivered: Vec<u32> = reliable
        .receive(server_packet(CONTROL, 0, vec![]))
        .iter()
        .map(|p| p.message_id)
        .collect();
    assert_eq!(delivered, [0, 1, 2]);
    let ack = reliable.ack_packet().unwrap();
    assert_eq!(ack.op, ACK);
    assert_eq!(ack.acks, [1, 2, 0]);
    assert_eq!(ack.ack_session, SERVER);
}

#[test]
fn a_duplicate_is_acked_again_but_not_delivered_twice() {
    let mut reliable = reliable();
    assert_eq!(reliable.receive(server_packet(CONTROL, 0, vec![])).len(), 1);
    reliable.ack_packet().unwrap();
    assert!(
        reliable
            .receive(server_packet(CONTROL, 0, vec![]))
            .is_empty()
    );
    assert_eq!(reliable.ack_packet().unwrap().acks, [0]);
}

#[test]
fn a_message_beyond_the_window_is_not_acked() {
    let mut reliable = reliable();
    assert!(
        reliable
            .receive(server_packet(CONTROL, 12, vec![]))
            .is_empty()
    );
    assert!(reliable.ack_packet().is_none());
    assert!(
        reliable
            .receive(server_packet(CONTROL, 11, vec![]))
            .is_empty()
    );
    assert_eq!(reliable.ack_packet().unwrap().acks, [11]);
}

#[test]
fn acks_are_capped_by_the_wrapper() {
    for (wrapped, cap) in [(true, 8), (false, 4)] {
        let mut reliable = Reliable::new(CLIENT, wrapped);
        reliable.remote = Some(SERVER);
        for id in 0..10 {
            reliable.receive(server_packet(CONTROL, id, vec![]));
        }
        assert_eq!(reliable.ack_packet().unwrap().acks.len(), cap);
        let message = reliable.message(CONTROL, vec![1]);
        assert!(message.acks.len() <= 4);
    }
}

#[test]
fn an_acked_message_is_not_retransmitted() {
    let mut reliable = reliable();
    let first = reliable.message(CONTROL, vec![1]);
    let second = reliable.message(CONTROL, vec![2]);
    assert_eq!((first.message_id, second.message_id), (0, 1));
    assert_eq!(reliable.retransmit().len(), 2);
    reliable.receive(server_packet(ACK, 0, vec![0]));
    let again = reliable.retransmit();
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].payload, [2]);
}

#[test]
fn a_soft_reset_opens_the_next_epoch_with_its_message_acked() {
    let mut reliable = reliable();
    reliable.receive(server_packet(CONTROL, 0, vec![]));
    reliable.message(CONTROL, vec![1]);
    let key_id = next_key_id(reliable.key_id);
    reliable.begin_epoch(key_id);
    reliable.delivered(0);
    assert_eq!(reliable.unacked(), 0);
    let reset = reliable.message(super::wire::SOFT_RESET, Vec::new());
    assert_eq!(
        (reset.key_id, reset.message_id, reset.acks.clone()),
        (1, 0, vec![0])
    );
    assert_eq!(reliable.receive(server_packet(CONTROL, 1, vec![])).len(), 1);
}

#[test]
fn next_key_id_skips_zero() {
    assert_eq!(next_key_id(0), 1);
    assert_eq!(next_key_id(6), 7);
    assert_eq!(next_key_id(7), 1);
}

#[test]
fn control_replay_rejects_zero_repeats_and_old_gaps() {
    let now = Instant::now();
    let mut replay = Replay::default();
    assert!(!replay.check(0, 100, now));
    assert!(replay.check(1, 100, now));
    assert!(!replay.check(1, 100, now));
    assert!(replay.check(3, 100, now));
    assert!(replay.check(2, 100, now));
    assert!(replay.check(70, 100, now));
    assert!(!replay.check(5, 100, now));
    assert!(replay.check(68, 100, now));
    assert!(!replay.check(69, 100, now + Duration::from_secs(16)));
    assert!(replay.check(71, 100, now));
    assert!(!replay.check(72, 99, now));
    assert!(replay.check(1, 101, now));
}

#[test]
fn push_reply_takes_mihomos_options() {
    let reply = PushReply::parse(
        "PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 8.8.8.8,ifconfig 10.8.0.2 255.255.255.0,peer-id 3,block-ipv6",
    )
    .unwrap();
    assert_eq!(reply.prefixes, ["10.8.0.2/24".parse().unwrap()]);
    assert_eq!(
        (reply.peer_id, reply.redirect, reply.block_ipv6),
        (3, true, true)
    );
    assert_eq!(reply.dns, ["8.8.8.8".parse::<std::net::IpAddr>().unwrap()]);

    let p2p = PushReply::parse(
        "PUSH_REPLY,dhcp-option DNS 10.211.254.254,ifconfig 10.211.1.37 10.211.254.254,peer-id 16777215",
    )
    .unwrap();
    assert_eq!(p2p.prefixes, ["10.211.1.37/32".parse().unwrap()]);

    let ciphers = PushReply::parse(
        "PUSH_REPLY,ncp-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305,cipher AES-256-GCM",
    )
    .unwrap();
    assert_eq!(
        ciphers.data_ciphers,
        strings(&["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"])
    );
    assert_eq!(ciphers.cipher, "AES-256-GCM");

    let rest = PushReply::parse(
        "PUSH_REPLY,route 10.9.0.0 255.255.0.0,route-ipv6 fd00::/64,ifconfig-ipv6 fd00::2/64 fd00::1,ping 10,ping-restart 120,auth-token tok,auth-token-user YWxpY2U=,push-continuation 2",
    )
    .unwrap();
    assert_eq!(
        rest.routes,
        ["10.9.0.0/16".parse().unwrap(), "fd00::/64".parse().unwrap()]
    );
    assert_eq!(rest.prefixes, ["fd00::2/64".parse().unwrap()]);
    assert_eq!(
        (rest.ping, rest.ping_restart, rest.continuation),
        (Some(10), Some(120), 2)
    );
    assert_eq!(
        (rest.auth_token.as_str(), rest.auth_token_user.as_str()),
        ("tok", "alice")
    );

    assert!(PushReply::parse("PUSH_REPLY,peer-id 16777216").is_err());
    assert!(PushReply::parse("PUSH_REPLY,push-continuation 3").is_err());
}

#[test]
fn inbox_splits_control_messages() {
    let mut inbox = Inbox::default();
    inbox
        .extend(
            b"AUTH_PENDING,timeout 9999999\0PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0\0AUTH_FAI",
        )
        .unwrap();
    assert!(
        matches!(inbox.next().unwrap(), Some(Message::AuthPending(d)) if d == Duration::from_secs(1800))
    );
    assert!(
        matches!(inbox.next().unwrap(), Some(Message::Push(reply)) if reply.prefixes.len() == 1)
    );
    assert!(inbox.next().unwrap().is_none());
    inbox.extend(b"LED,bad password\0").unwrap();
    assert!(
        matches!(inbox.next().unwrap(), Some(Message::Failed(reason)) if reason.contains("bad password"))
    );
}

#[test]
fn cipher_negotiation_follows_mihomo() {
    let plain = config(|_| {});
    let negotiate = |config: &Config, pushed: &[&str], cipher: &str| {
        config
            .negotiated_name(&strings(pushed), cipher)
            .map_err(|e| e.to_string())
    };
    let name = |text: &str| Ok(text.to_string());
    assert_eq!(negotiate(&plain, &[], ""), name("AES-128-GCM"));
    assert_eq!(negotiate(&plain, &[], "AES-128-GCM"), name("AES-128-GCM"));
    assert_eq!(negotiate(&plain, &[], "AES-256-GCM"), name("AES-256-GCM"));

    let listed = config(|o| o.data_ciphers = strings(&["AES-256-GCM", "AES-128-GCM"]));
    assert_eq!(
        negotiate(&listed, &["AES-128-GCM", "AES-256-GCM"], ""),
        name("AES-128-GCM")
    );

    let only = config(|o| o.data_ciphers = strings(&["AES-256-GCM"]));
    assert!(negotiate(&only, &["CHACHA20-POLY1305"], "").is_err());
    let fallback = config(|o| {
        o.data_ciphers = strings(&["AES-256-GCM"]);
        o.data_ciphers_fallback = "AES-128-CBC".into();
    });
    assert_eq!(
        negotiate(&fallback, &["CHACHA20-POLY1305"], ""),
        name("AES-128-CBC")
    );
}

#[test]
fn pushed_keepalive_applies_only_where_the_node_sets_none() {
    let push = PushReply {
        ping: Some(10),
        ping_restart: Some(120),
        ..PushReply::default()
    };
    assert_eq!(
        keepalive_timers(&config(|_| {}), &push),
        (
            Some(Duration::from_secs(10)),
            Some(Duration::from_secs(120))
        )
    );
    assert_eq!(
        keepalive_timers(&config(|o| o.ping = 5), &push),
        (Some(Duration::from_secs(5)), Some(Duration::from_secs(120)))
    );
    assert_eq!(
        keepalive_timers(&config(|_| {}), &PushReply::default()),
        (None, None)
    );
}

fn material() -> KeyMaterial {
    KeyMaterial {
        send_cipher: [0x11; 64],
        send_hmac: [0x22; 64],
        recv_cipher: [0x33; 64],
        recv_hmac: [0x44; 64],
    }
}

fn mirrored(material: &KeyMaterial) -> KeyMaterial {
    KeyMaterial {
        send_cipher: material.recv_cipher,
        send_hmac: material.recv_hmac,
        recv_cipher: material.send_cipher,
        recv_hmac: material.send_hmac,
    }
}

fn pair(cipher: &str, digest: Digest, peer_id: u32) -> (DataKey, DataKey) {
    let cipher = Cipher::parse(cipher).unwrap();
    let client = DataKey::new(&material(), cipher, digest, peer_id, 1).unwrap();
    let server = DataKey::new(&mirrored(&material()), cipher, digest, peer_id, 1).unwrap();
    (client, server)
}

fn open(key: &DataKey, packet: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0; packet.len()];
    let (start, end) = key.open(packet, &mut out).ok()?;
    Some(out[start..end].to_vec())
}

#[test]
fn data_round_trips_every_cipher_and_rejects_replays() {
    for cipher in [
        "AES-128-GCM",
        "AES-256-GCM",
        "CHACHA20-POLY1305",
        "AES-128-CBC",
        "AES-256-CBC",
    ] {
        for peer_id in [3, super::push::PEER_ID_UNSET] {
            let (client, server) = pair(cipher, Digest::Sha256, peer_id);
            let mut sealed = Vec::new();
            client.seal(&[], b"hello", &mut sealed).unwrap();
            assert_eq!(
                open(&server, &sealed).as_deref(),
                Some(&b"hello"[..]),
                "{cipher}"
            );
            assert!(open(&server, &sealed).is_none(), "{cipher} replay");
            let mut later = Vec::new();
            client.seal(&[], b"again", &mut later).unwrap();
            let last = later.len() - 1;
            later[last] ^= 1;
            assert!(open(&server, &later).is_none(), "{cipher} tamper");
        }
    }
}

#[test]
fn pings_carry_the_comp_lzo_header() {
    let (client, server) = pair("AES-128-GCM", Digest::Sha256, 1);
    let keys = Keys::first(std::sync::Arc::new(server));
    let pool = PacketBufPool::new(0);
    let now = Instant::now();
    let mut sealed = Vec::new();
    client.seal(lzo_prefix(true), &PING, &mut sealed).unwrap();
    let mut seen = vec![0; sealed.len()];
    let (start, _) = keys.primary.open(&sealed, &mut seen).unwrap();
    assert_eq!(seen[start], 0xFA);
    client.seal(lzo_prefix(true), &PING, &mut sealed).unwrap();
    assert!(matches!(
        open_data(&sealed, &keys, true, &pool, now),
        Some(Opened::Nothing)
    ));

    client
        .seal(lzo_prefix(true), b"\x45packet", &mut sealed)
        .unwrap();
    let Some(Opened::Packet(packet)) = open_data(&sealed, &keys, true, &pool, now) else {
        panic!("a framed packet opens");
    };
    assert_eq!(&packet[..], b"\x45packet");

    client.seal(&[0x2a], b"bad header", &mut sealed).unwrap();
    assert!(matches!(
        open_data(&sealed, &keys, true, &pool, now),
        Some(Opened::Nothing)
    ));
    sealed[1] ^= 0xff;
    assert!(open_data(&sealed, &keys, true, &pool, now).is_none());
}

#[test]
fn static_keys_parse_as_openvpn_writes_them() {
    let hex: String = (0..=255u8).map(|b| format!("{b:02x}")).collect();
    let lines: Vec<&str> = hex
        .as_bytes()
        .chunks(32)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    let text = format!(
        "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n{}\n-----END OpenVPN Static key V1-----\n",
        lines.join("\n")
    );
    let key = static_key(&text, "tls-auth").unwrap();
    assert_eq!(key.as_flattened(), (0..=255u8).collect::<Vec<_>>());
    assert!(static_key(&lines[..10].join("\n"), "tls-auth").is_err());

    use base64::Engine;
    let mut v2 = key.as_flattened().to_vec();
    v2.extend_from_slice(b"wrapped client key");
    let pem = format!(
        "-----BEGIN OpenVPN tls-crypt-v2 client key-----\n{}\n-----END OpenVPN tls-crypt-v2 client key-----\n",
        base64::engine::general_purpose::STANDARD.encode(&v2)
    );
    let (material, wrapped) = tls_crypt_v2(&pem).unwrap();
    assert_eq!((material, wrapped), (key, b"wrapped client key".to_vec()));
}

#[test]
fn wrappers_round_trip_between_the_two_ends() {
    let key = super::wrap::static_key(&(0..=255u8).collect::<Vec<_>>()).unwrap();
    let header = [0x38, 1, 2, 3, 4, 5, 6, 7, 8];
    for (client, server) in [
        (
            Wrap::auth(&key, "1", Digest::Sha256),
            Wrap::auth(&key, "0", Digest::Sha256),
        ),
        (
            Wrap::auth(&key, "", Digest::Sha1),
            Wrap::auth(&key, "", Digest::Sha1),
        ),
    ] {
        let sealed = client.seal(&header, 7, 1_714_567_890, b"hello").unwrap();
        let opened = server.open(&sealed).unwrap();
        assert_eq!(
            (opened.header, opened.packet_id, opened.time),
            (header, 7, 1_714_567_890)
        );
        assert_eq!(opened.plain, b"hello");
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(server.open(&tampered).is_err());
    }
}

#[test]
fn options_and_peer_info_match_mihomo() {
    let options = options_string(true, "AES-256-CBC", "SHA1", false);
    for want in [
        "proto TCPv4_CLIENT",
        "cipher AES-256-CBC",
        "auth SHA1",
        "keysize 256",
        "link-mtu 1550",
    ] {
        assert!(options.contains(want), "{options}");
    }
    assert!(
        options_string(false, "AES-128-GCM", "SHA256", true)
            .contains("link-mtu 1544,tun-mtu 1500,proto UDPv4,comp-lzo,")
    );
    let base = peer_info(&strings(&["AES-128-GCM"]), false, &Default::default());
    assert_eq!(
        base,
        "IV_VER=mihomo-openvpn\nIV_PROTO=22\nIV_CIPHERS=AES-128-GCM\n"
    );
    let extra = [
        ("UV_DEVICE_ID", "laptop-001"),
        ("IV_HWADDR", "52:54:00:ff:72:87"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    assert_eq!(
        peer_info(&strings(&["AES-128-GCM"]), false, &extra),
        format!("{base}IV_HWADDR=52:54:00:ff:72:87\nUV_DEVICE_ID=laptop-001\n")
    );
    let overridden = [
        ("IV_VER", "custom-client/1.0"),
        ("IV_PROTO", "999"),
        ("IV_LZO", "0"),
        ("IV_CIPHERS", "AES-256-CBC"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    assert_eq!(
        peer_info(&strings(&["AES-128-GCM"]), true, &overridden),
        "IV_VER=custom-client/1.0\nIV_PROTO=22\nIV_LZO=1\nIV_CIPHERS=AES-128-GCM\n"
    );
}

fn server_record(options: &str, tail: &[&str], extra: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0, 0, 2];
    packet.extend([1; 32]);
    packet.extend([2; 32]);
    for text in std::iter::once(&options).chain(tail) {
        let len = u16::try_from(text.len() + 1).unwrap();
        packet.extend(len.to_be_bytes());
        packet.extend(text.as_bytes());
        packet.push(0);
    }
    packet.extend(extra);
    packet
}

#[test]
fn server_records_parse_whole_or_shortened() {
    let full = server_record("server-options", &["", "", "IV_VER=server\n"], b"");
    assert_eq!(parse_server(&full).unwrap().unwrap().1, full.len());
    assert!(parse_server(&full[..full.len() - 3]).unwrap().is_none());

    let push = b"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0\0";
    let short = server_record("server-options", &[], push);
    let (_, used) = parse_server(&short).unwrap().unwrap();
    assert!(short[used..].starts_with(b"PUSH_REPLY"));
}
