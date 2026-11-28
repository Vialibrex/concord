#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "the tests assert on fixed shapes"
)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use blake2::digest::consts::U16;
use blake2::digest::{Digest, Mac};
use blake2::{Blake2s256, Blake2sMac};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use super::*;

const A: [u8; 32] = [0xa1; 32];
const B: [u8; 32] = [0xb2; 32];

fn from() -> SocketAddr {
    "192.0.2.1:51820".parse().unwrap()
}

fn settings(opts: AmneziaWgOpts) -> Arc<Settings> {
    Arc::new(Settings::parse(&opts).unwrap().unwrap())
}

fn pair(opts: AmneziaWgOpts) -> (Amnezia, Amnezia) {
    let settings = settings(opts);
    let a = Amnezia::new(settings.clone(), &A, &[B]);
    let b = Amnezia::new(settings, &B, &[A]);
    (a, b)
}

fn legacy() -> AmneziaWgOpts {
    AmneziaWgOpts {
        jc: 4,
        jmin: 20,
        jmax: 60,
        s1: 15,
        s2: 27,
        s3: 9,
        s4: 5,
        h: [
            "1234567".into(),
            "7654321-7654999".into(),
            "11111".into(),
            "22222".into(),
        ],
        ..AmneziaWgOpts::default()
    }
}

fn v3() -> AmneziaWgOpts {
    AmneziaWgOpts {
        version: 3,
        jc: 2,
        jmin: 30,
        jmax: 50,
        s1: 20,
        s2: 21,
        s3: 22,
        s4: 23,
        h: [
            "100000-200000".into(),
            "300000-400000".into(),
            "500000-600000".into(),
            "700000-800000".into(),
        ],
        header_protection_key: STANDARD.encode([7u8; 32]),
        random_trailers: true,
        ..AmneziaWgOpts::default()
    }
}

fn handshake(kind: u32, len: usize, recipient: &[u8; 32]) -> Vec<u8> {
    let mut message: Vec<u8> = (0..len).map(|i| (i * 13 % 251) as u8).collect();
    message[..4].copy_from_slice(&kind.to_le_bytes());
    Macs::new(recipient).stamp(&mut message, false);
    message
}

fn transport(len: usize) -> Vec<u8> {
    let mut packet: Vec<u8> = (0..len).map(|i| (i * 7 % 253) as u8).collect();
    packet[..4].copy_from_slice(&4u32.to_le_bytes());
    packet
}

async fn handshake_round_trip(opts: AmneziaWgOpts) {
    let (a, b) = pair(opts);
    for (kind, len) in [(1, INITIATION), (2, RESPONSE)] {
        let message = handshake(kind, len, &B);
        let mut wire = a.frame(&message, from()).await;
        let mut last = wire.pop().unwrap();
        for junk in &mut wire {
            assert!(b.unframe(junk, from()).is_none());
        }
        let kept = b.unframe(&mut last, from()).unwrap();
        assert_eq!(&last[..kept], &message[..]);
    }
}

async fn transport_round_trip(opts: AmneziaWgOpts) {
    let (a, b) = pair(opts);
    for len in [32, 33, 1400] {
        let packet = transport(len);
        let mut wire = a.frame(&packet, from()).await;
        assert_eq!(wire.len(), 1);
        let mut datagram = wire.pop().unwrap();
        assert_ne!(datagram[..4], packet[..4]);
        let kept = b.unframe(&mut datagram, from()).unwrap();
        assert_eq!(&datagram[..kept], &packet[..]);
    }
}

#[tokio::test]
async fn legacy_handshakes_survive_framing() {
    handshake_round_trip(legacy()).await;
}

#[tokio::test]
async fn legacy_transport_survives_framing() {
    transport_round_trip(legacy()).await;
}

#[tokio::test]
async fn protected_handshakes_survive_framing() {
    handshake_round_trip(v3()).await;
}

#[tokio::test]
async fn protected_transport_survives_framing() {
    transport_round_trip(v3()).await;
}

#[tokio::test]
async fn an_init_is_preceded_by_junk_and_the_wire_type_is_replaced() {
    let (a, _) = pair(legacy());
    let wire = a.frame(&handshake(1, INITIATION, &B), from()).await;
    assert_eq!(wire.len(), 5);
    let init = wire.last().unwrap();
    assert_eq!(init.len(), INITIATION + 15);
    let ty = u32::from_le_bytes(init[15..19].try_into().unwrap());
    assert_eq!(ty, 1_234_567);
    assert!(wire[..4].iter().all(|junk| (20..60).contains(&junk.len())));
}

#[tokio::test]
async fn a_message_with_a_wrong_mac_is_dropped() {
    let (a, b) = pair(legacy());
    let mut wire = a.frame(&handshake(1, INITIATION, &B), from()).await;
    let mut last = wire.pop().unwrap();
    last[40] ^= 1;
    assert!(b.unframe(&mut last, from()).is_none());
}

#[test]
fn check_mac1_accepts_valid_and_rejects_tampered_or_short_messages() {
    let macs = Macs::new(&B);
    for (kind, len) in [(1, INITIATION), (2, RESPONSE)] {
        let valid = handshake(kind, len, &B);
        assert!(macs.check_mac1(&valid));

        let mut bad_first = valid.clone();
        bad_first[len - 32] ^= 1;
        assert!(!macs.check_mac1(&bad_first));

        let mut bad_last = valid.clone();
        bad_last[len - 17] ^= 1;
        assert!(!macs.check_mac1(&bad_last));

        let mut bad_body = valid.clone();
        bad_body[8] ^= 1;
        assert!(!macs.check_mac1(&bad_body));
    }
    for len in 0..32 {
        assert!(!macs.check_mac1(&vec![0u8; len]));
    }
}

#[tokio::test]
async fn a_cookie_reply_sets_mac2_on_the_next_initiation() {
    let (a, _) = pair(legacy());
    let first = a
        .frame(&handshake(1, INITIATION, &B), from())
        .await
        .pop()
        .unwrap();
    let body = &first[15..];
    let mac1: [u8; 16] = body[116..132].try_into().unwrap();
    assert_eq!(&body[132..], &[0u8; 16]);

    let mut key = Blake2s256::new();
    key.update(b"cookie--");
    key.update(B);
    let cookie = [0x5a; 16];
    let nonce = [9u8; 24];
    let sealed = XChaCha20Poly1305::new_from_slice(&key.finalize())
        .unwrap()
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &cookie,
                aad: &mac1,
            },
        )
        .unwrap();
    let mut reply = Vec::new();
    reply.extend_from_slice(&11111u32.to_le_bytes());
    reply.extend_from_slice(&[0; 4]);
    reply.extend_from_slice(&nonce);
    reply.extend_from_slice(&sealed);
    let mut datagram = vec![0u8; 9];
    datagram.extend_from_slice(&reply);
    assert!(a.unframe(&mut datagram, from()).is_none());

    let second = a
        .frame(&handshake(1, INITIATION, &B), from())
        .await
        .pop()
        .unwrap();
    let body = &second[15..];
    let mut mac = Blake2sMac::<U16>::new_from_slice(&cookie).unwrap();
    mac.update(&body[..132]);
    assert_eq!(&body[132..], mac.finalize().into_bytes().as_slice());
}

#[test]
fn options_that_change_nothing_leave_the_tunnel_plain() {
    assert!(
        Settings::parse(&AmneziaWgOpts::default())
            .unwrap()
            .is_none()
    );
    let defaults = AmneziaWgOpts {
        h: ["1".into(), "2".into(), "3".into(), "4".into()],
        ..AmneziaWgOpts::default()
    };
    assert!(Settings::parse(&defaults).unwrap().is_none());
}

#[test]
fn legacy_options_are_checked_like_amneziawg_go() {
    let bad = |edit: fn(&mut AmneziaWgOpts)| {
        let mut opts = legacy();
        edit(&mut opts);
        Settings::parse(&opts).is_err()
    };
    assert!(bad(|o| o.jmax = 10));
    assert!(bad(|o| o.jmax = 70_000));
    assert!(bad(|o| o.h[1] = "1234567".into()));
    assert!(bad(|o| o.h[0] = "9-2".into()));
    assert!(bad(|o| o.s2 = o.s1 + 56));
    assert!(bad(|o| o.i[1] = "<r 5>".into()));
    assert!(bad(|o| o.header_protection_key = STANDARD.encode([1u8; 32])));
    assert!(bad(|o| o.random_trailers = true));
    assert!(!bad(|o| o.i[0] = "<b 0xdead><r 5>".into()));
}

#[test]
fn version_three_options_are_checked_like_amneziawg_go() {
    let bad = |edit: fn(&mut AmneziaWgOpts)| {
        let mut opts = v3();
        edit(&mut opts);
        Settings::parse(&opts).is_err()
    };
    assert!(bad(|o| o.h[1] = "150000-350000".into()));
    assert!(bad(|o| o.s2 = 8));
    assert!(bad(|o| o.header_protection_key = STANDARD.encode([1u8; 16])));
    assert!(bad(|o| o.j[0] = "<r 5>".into()));
    assert!(bad(|o| o.itime = 5));
    assert!(bad(|o| o.i[0] = "<q 5>".into()));
    assert!(!bad(|o| o.i[0] = "<b 0xdead><t><rc 5><rd 3><dz 2>".into()));
}

#[tokio::test]
async fn templates_render_the_tags_they_name() {
    let counter = AtomicU64::new(5);
    let legacy =
        template::parse_legacy("<b 0xf6ab3267fa><c><b 0xf6ab><t><r 10><rc 4><rd 3>").unwrap();
    let bytes = legacy.render(&counter).await;
    assert_eq!(bytes.len(), 5 + 8 + 2 + 8 + 10 + 4 + 3);
    assert_eq!(&bytes[..5], &[0xf6, 0xab, 0x32, 0x67, 0xfa]);
    assert_eq!(&bytes[5..13], &5u64.to_be_bytes());
    assert!(bytes[bytes.len() - 3..].iter().all(u8::is_ascii_digit));
    assert!(template::parse_legacy("<c><c>").is_err());
    assert!(template::parse_legacy("<r 5000>").is_err());
    assert!(template::parse_legacy("<b dead>").is_err());
    assert!(template::parse_legacy("nothing").is_err());

    let chain = template::parse_chain("<b 0x0102><t><r 3><dz 2><d><ds>").unwrap();
    let bytes = chain.render(&counter).await;
    assert_eq!(bytes.len(), 2 + 4 + 3 + 2);
    assert_eq!(&bytes[..2], &[1, 2]);
}
