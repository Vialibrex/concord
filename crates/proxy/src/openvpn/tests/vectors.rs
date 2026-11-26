//! Bytes mihomo `3f27ef39`'s `transport/openvpn` produced for the same inputs. Its data
//! channel takes the cipher key as given, so the 32-byte test keys select AES-256 whatever
//! the AES name; each case here names the cipher that actually ran.

use indexmap::IndexMap;

use super::super::data::{Cipher, DataKey};
use super::super::keys::{
    ClientRecord, Credentials, Digest, options_string, parse_server, peer_info,
};
use super::super::wire::{CONTROL, ControlPacket};
use super::super::wrap::{Wrap, static_key};
use super::{CLIENT, SERVER, material, mirrored, open, strings};

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap()
}

const HEADER: [u8; 9] = [0x38, 1, 2, 3, 4, 5, 6, 7, 8];
const PLAIN: &[u8] = b"client hello over openvpn control channel";
const TIME: u32 = 1_714_567_890;

fn key() -> super::super::wrap::StaticKey {
    static_key(&(0..=255u8).collect::<Vec<_>>()).unwrap()
}

#[test]
fn tls_auth_matches_mihomo() {
    let cases = [
        (
            Digest::Sha1,
            "1",
            "dd8cadf9d22b1cf96c7ece953480ed24695d32ef",
        ),
        (
            Digest::Sha1,
            "0",
            "b3de044a6f8a2b8bfe9af615810aa319d1704713",
        ),
        (Digest::Sha1, "", "b3de044a6f8a2b8bfe9af615810aa319d1704713"),
        (
            Digest::Sha256,
            "1",
            "2011231d5ca57684ed41e9fbe098e375eaec6014158468fc25b5c61a5ed806c4",
        ),
        (
            Digest::Sha256,
            "0",
            "301e230be32bd25bc47c10bffbf96b6857b80fd0c2bfc4fd93c8e055a687241a",
        ),
        (
            Digest::Sha512,
            "1",
            "f90fff66e96279119e5e8ee515de8bc0ab0f0e4fee5eacea20e09f9d3f9fc5479168f2030bc5028eb250d211f5ee19380cd626d75c7b2bd358f988d7c35d6e0b",
        ),
        (Digest::Md5, "1", "90aa5c0c292b1c6ed52f7f676897b222"),
        (Digest::Md5, "0", "9ed331edf4b1b62b5ce297a2e43e686f"),
    ];
    for (digest, direction, tag) in cases {
        let sealed = Wrap::auth(&key(), direction, digest)
            .seal(&HEADER, 7, TIME, PLAIN)
            .unwrap();
        let want = [&HEADER[..], &unhex(tag), &unhex("0000000766323ad2"), PLAIN].concat();
        assert_eq!(sealed, want, "{direction:?}");
    }
}

#[test]
fn tls_crypt_matches_mihomo() {
    let client = Wrap::crypt(&key(), None);
    let sealed = client.seal(&HEADER, 7, TIME, PLAIN).unwrap();
    assert_eq!(
        sealed,
        unhex(
            "3801020304050607080000000766323ad2d9b86357201263af3f72dc776e86bf935b0831c01cacc246ebd897f987478d4fcc92dcbba02af2d398f4789f261262e725302defcba25f3538904d5822f9a44f96b71069853658dd76"
        )
    );
    let from_server = unhex(
        "3801020304050607080000000966323ad3740288387dd5b3177281bc0bf251c64641c4d3baa2641d13982d7a08a42907b674043590a65bf6201af2fbf8db398796aa5c455c69e443bfca96ee7d1c30a110b8dc02f886c3de8b51",
    );
    let opened = client.open(&from_server).unwrap();
    assert_eq!(
        (opened.header, opened.packet_id, opened.time),
        (HEADER, 9, TIME + 1)
    );
    assert_eq!(opened.plain, PLAIN);
}

fn fixed_record() -> ClientRecord {
    let mut pre_master = [0; 48];
    let mut random1 = [0; 32];
    let mut random2 = [0; 32];
    for (i, b) in pre_master.iter_mut().enumerate() {
        *b = i as u8 + 1;
    }
    for i in 0..32 {
        random1[i] = i as u8 + 2;
        random2[i] = i as u8 + 3;
    }
    ClientRecord::fixed(pre_master, random1, random2)
}

#[test]
fn key_method_2_matches_mihomo() {
    let mut server = vec![0, 0, 0, 0, 2];
    server.extend((0..32u8).map(|i| i + 4));
    server.extend((0..32u8).map(|i| i + 5));
    server.extend([0; 8]);
    let (server, _) = parse_server(&server).unwrap().unwrap();
    let keys = fixed_record().derive(&server, &CLIENT, &SERVER);
    assert_eq!(
        keys.send_cipher[..32],
        unhex("398bb7e7f3e55b4ec9b663bc44d04696d29d61d207598f396b2f56c74e06e1ba")
    );
    assert_eq!(
        keys.send_hmac[..],
        unhex(
            "cf5ddca2c0f9b86d98363c83c7c3a372e0c4a62b6f06239d8446c6ddfa6a903da4d2df1c1014ac3a1bf8932fd439b19b558ab3653be3eabeabb9ea548fb0c784"
        )
    );
    assert_eq!(
        keys.recv_cipher[..32],
        unhex("81693cfb38abb5f88039763eb4c9450b0ec614b45bf8dfe52ebce363e7accd1a")
    );
    assert_eq!(
        keys.recv_hmac[..],
        unhex(
            "317dab8cd211fe399a685370e996026b167d3a084fabd4f549b61e059d1fac57e4280885640e9f79b03b37756739f8798e418c24eb2883021e67864a4066186b"
        )
    );

    let options = options_string(false, "AES-256-GCM", "SHA256", true);
    assert_eq!(
        options,
        "V4,dev-type tun,link-mtu 1544,tun-mtu 1500,proto UDPv4,comp-lzo,cipher AES-256-GCM,auth SHA256,keysize 256,key-method 2,tls-client"
    );
    assert_eq!(
        options_string(true, "AES-128-CBC", "SHA1", false),
        "V4,dev-type tun,link-mtu 1550,tun-mtu 1500,proto TCPv4_CLIENT,cipher AES-128-CBC,auth SHA1,keysize 128,key-method 2,tls-client"
    );
    let extra: IndexMap<String, String> = [("UV_X".to_string(), "1".to_string())]
        .into_iter()
        .collect();
    let info = peer_info(
        &strings(&["AES-256-GCM", "CHACHA20-POLY1305"]),
        true,
        &extra,
    );
    assert_eq!(
        info,
        "IV_VER=mihomo-openvpn\nIV_PROTO=22\nIV_LZO=1\nIV_CIPHERS=AES-256-GCM:CHACHA20-POLY1305\nUV_X=1\n"
    );
    let encoded = fixed_record().encode(&Credentials {
        options: &options,
        username: "alice",
        password: "secret",
        peer_info: &info,
    });
    assert_eq!(
        encoded,
        unhex(
            "00000000020102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122008356342c6465762d747970652074756e2c6c696e6b2d6d747520313534342c74756e2d6d747520313530302c70726f746f2055445076342c636f6d702d6c7a6f2c636970686572204145532d3235362d47434d2c61757468205348413235362c6b657973697a65203235362c6b65792d6d6574686f6420322c746c732d636c69656e74000006616c69636500000773656372657400005c49565f5645523d6d69686f6d6f2d6f70656e76706e0a49565f50524f544f3d32320a49565f4c5a4f3d310a49565f434950484552533d4145532d3235362d47434d3a43484143484132302d504f4c59313330350a55565f583d310a00"
        )
    );
}

const IP_PACKET: [u8; 20] = [
    0x45, 0, 0, 20, 1, 2, 3, 4, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1,
];

#[test]
fn aead_data_packets_match_mihomo() {
    let cases = [
        (
            "AES-256-GCM",
            Digest::Sha256,
            0x12_3456,
            1,
            [
                "4912345600000001221d4f97d95a3c3a9bae4170e1c019ce8ed60d5c2fa034736e10198fd7a41a4ccd6af004",
                "4912345600000002123827709c2ea85a984700d51c059308cc8d15e9356cc657468e12a0892f4616a5aed8a6",
            ],
        ),
        (
            "AES-256-GCM",
            Digest::Sha1,
            super::super::push::PEER_ID_UNSET,
            4,
            [
                "340000000108f6ba62f8a71601bb1b2d7c9eb7c4f68ed60d5c2fa034736e10198fd7a41a4ccd6af004",
                "34000000021ee74ed8433c712c36fe221d6a895df1cc8d15e9356cc657468e12a0892f4616a5aed8a6",
            ],
        ),
        (
            "CHACHA20-POLY1305",
            Digest::Sha256,
            7,
            2,
            [
                "4a00000700000001565775c7293b1280ad1cb9ab88a5e10a1c796a6d8825aef3a6cf23761547dc783b1d49ef",
                "4a00000700000002ae9e51f69d236266f890cc2be222bf0f3186f0477aa7bac92a42bc55f3def1ee8e6f8519",
            ],
        ),
    ];
    for (name, digest, peer_id, key_id, packets) in cases {
        let cipher = Cipher::parse(name).unwrap();
        let client = DataKey::new(&material(), cipher, digest, peer_id, key_id).unwrap();
        let server = DataKey::new(&mirrored(&material()), cipher, digest, peer_id, key_id).unwrap();
        for packet in packets {
            let mut sealed = Vec::new();
            client.seal(&[], &IP_PACKET, &mut sealed).unwrap();
            assert_eq!(sealed, unhex(packet), "{name}");
            assert_eq!(open(&server, &unhex(packet)).unwrap(), IP_PACKET, "{name}");
        }
    }
}

#[test]
fn cbc_data_packets_from_mihomo_open() {
    let cases = [
        (
            "AES-256-CBC",
            Digest::Sha256,
            5,
            [
                "49000005362c27683cb32fd2facd0ba56c6bc2ff33651a7f1306a450356b4bc4587a3caabcf8eb00d2961e009fc233d6419703fb6a7359264773a97a0864b65ddf93d758fbca7747c29cd49bd769354c412703b3",
                "49000005ffe96f1d7c9b88b9c086ae6b3f08ec6cfc6ffa3e4723c8a48a519ae666d0323dcae9ac64eb7d74dac2938d26a3545cc117db931e82e2642ccd35155fbb483700f01ea62b34b300e99c1d6497a6d2bee9",
            ],
        ),
        (
            "AES-256-CBC",
            Digest::Sha1,
            super::super::push::PEER_ID_UNSET,
            [
                "33332e94aff8749233916edfb81b2bec6667087260e84b31861c2c6f0f6bb516c647f0b08ecfdc0801877909ab2c507a88e8eb89f2de69e4a93282324f2d42df46abc318d0",
                "33a811ba0d9520c5c6245a6dcac88ff0a1eec06031488c164ba2d0ae0a2be52a429646c708dc55195f9bb81d3f34c4a1fae0747472b66a1fe8a6e102b63bc29e94662816e8",
            ],
        ),
    ];
    for (name, digest, peer_id, packets) in cases {
        let cipher = Cipher::parse(name).unwrap();
        let server = DataKey::new(&mirrored(&material()), cipher, digest, peer_id, 1).unwrap();
        let client = DataKey::new(&material(), cipher, digest, peer_id, 1).unwrap();
        for packet in packets {
            assert_eq!(open(&server, &unhex(packet)).unwrap(), IP_PACKET, "{name}");
        }
        let mut sealed = Vec::new();
        client.seal(&[], &IP_PACKET, &mut sealed).unwrap();
        assert_eq!(sealed.len(), unhex(packets[0]).len(), "{name}");
    }
}

#[test]
fn control_plain_matches_mihomo() {
    let packet = ControlPacket {
        op: CONTROL,
        key_id: 2,
        session: CLIENT,
        acks: vec![3, 4],
        ack_session: SERVER,
        message_id: 9,
        payload: b"tls".to_vec(),
    };
    let plain = packet.plain();
    assert_eq!(
        plain,
        unhex("020000000300000004736572766572303100000009746c73")
    );
    assert_eq!(
        packet.header(),
        [0x22, b'c', b'l', b'i', b'e', b'n', b't', b'0', b'1']
    );
    assert_eq!(
        ControlPacket::decode(&packet.header(), &plain).unwrap(),
        packet
    );
}
