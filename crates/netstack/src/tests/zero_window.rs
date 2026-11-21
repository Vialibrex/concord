use super::*;
use crate::wire::{FLAG_ACK, TcpSegment};

fn segment(packet: &[u8]) -> TcpSegment<'_> {
    let Ok(Parsed::Packet(view)) = parse_packet(packet) else {
        panic!("invalid packet");
    };
    parse_tcp(view.l4).unwrap()
}

fn from_peer(stack: &mut TcpStack, out: &mut Wire, header: TcpHeader, payload: &[u8]) {
    let mut packet = vec![0; 2048];
    let options = TcpOptions {
        mss: (header.flags & FLAG_SYN != 0).then_some(1460),
        ..TcpOptions::default()
    };
    let len = emit_tcp(
        &mut packet,
        &header,
        &options,
        payload.len(),
        L4Checksum::Full,
        |body| {
            body.copy_from_slice(payload);
            Some(())
        },
    )
    .unwrap();
    let Ok(Parsed::Packet(view)) = parse_packet(&packet[..len]) else {
        panic!("invalid peer packet");
    };
    assert_eq!(
        stack.input(view.src, view.dst, view.l4, out, |_, _| Admit::Reject),
        TcpInput::Handled
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_ack_in_a_closed_peer_window_releases_duplex_backpressure() {
    for window in [0, 1024] {
        let mut stack = TcpStack::new(StackConfig::default());
        let mut out = Wire::default();
        let (local, remote) = addrs();
        let mut stream = stack.connect(local, remote, Congestion::Cubic).unwrap();
        stack.poll(&mut out);
        let start = segment(&out.packets.pop().unwrap()).seq.wrapping_add(1);
        let peer_start = u32::MAX - 2000;
        from_peer(
            &mut stack,
            &mut out,
            TcpHeader {
                src: remote,
                dst: local,
                seq: peer_start.wrapping_sub(1),
                ack: start,
                flags: FLAG_SYN | FLAG_ACK,
                window: 48,
            },
            &[],
        );
        stack.poll(&mut out);
        out.packets.clear();
        stream.write_all(&[7; 48]).await.unwrap();
        stack.poll(&mut out);
        let in_flight = out.packets.pop().unwrap();
        assert_eq!(segment(&in_flight).payload, &[7; 48]);
        out.packets.clear();

        let reply = pattern(2920, 3);
        for (i, payload) in reply.chunks(1460).enumerate() {
            from_peer(
                &mut stack,
                &mut out,
                TcpHeader {
                    src: remote,
                    dst: local,
                    seq: peer_start.wrapping_add((i * 1460) as u32),
                    ack: start,
                    flags: FLAG_ACK,
                    window,
                },
                payload,
            );
        }
        stack.poll(&mut out);
        let packet = out.packets.pop().unwrap();
        let ack = segment(&packet);
        assert!(ack.payload.is_empty());
        assert_eq!(ack.ack, peer_start.wrapping_add(reply.len() as u32));
        if window == 0 {
            // A strict zero-window receiver accepts only RCV.NXT, even for an ACK.
            assert_eq!(
                ack.seq, start,
                "the peer must accept the ACK to drain its echo queue"
            );
        } else {
            assert_eq!(ack.seq, start.wrapping_add(48));
        }
        let mut received = vec![0; reply.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, reply);
        stream.write_all(&[9; 48]).await.unwrap();
        out.packets.clear();

        from_peer(
            &mut stack,
            &mut out,
            TcpHeader {
                src: remote,
                dst: local,
                seq: ack.ack,
                ack: start.wrapping_add(48),
                flags: FLAG_ACK,
                window: 48,
            },
            &[],
        );
        stack.poll(&mut out);
        let packet = out.packets.pop().unwrap();
        let resumed = segment(&packet);
        assert_eq!(resumed.seq, start.wrapping_add(48));
        assert_eq!(resumed.payload, &[9; 48]);
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_ack_at_the_right_edge_of_a_filled_window_is_taken() {
    let mut stack = TcpStack::new(StackConfig::default());
    let mut out = Wire::default();
    let (local, remote) = addrs();
    let mut stream = stack.connect(local, remote, Congestion::Cubic).unwrap();
    stack.poll(&mut out);
    let start = segment(&out.packets.pop().unwrap()).seq.wrapping_add(1);
    let peer_start = u32::MAX - 2000;
    let from = |seq: u32, ack: u32, window: u16| TcpHeader {
        src: remote,
        dst: local,
        seq,
        ack,
        flags: FLAG_ACK,
        window,
    };
    from_peer(
        &mut stack,
        &mut out,
        TcpHeader {
            flags: FLAG_SYN | FLAG_ACK,
            ..from(peer_start.wrapping_sub(1), start, 48)
        },
        &[],
    );
    stack.poll(&mut out);
    let advertised = u32::from(segment(&out.packets.pop().unwrap()).window);
    out.packets.clear();
    stream.write_all(&[7; 48]).await.unwrap();
    stack.poll(&mut out);
    assert_eq!(segment(&out.packets.pop().unwrap()).payload, &[7; 48]);

    // The first segment of the window is lost; the peer fills the rest of it.
    let edge = peer_start.wrapping_add(advertised);
    let mut seq = peer_start.wrapping_add(1460);
    while seq != edge {
        let len = edge.wrapping_sub(seq).min(1460) as usize;
        from_peer(&mut stack, &mut out, from(seq, start, 48), &pattern(len, 5));
        seq = seq.wrapping_add(len as u32);
    }
    // Its pure ACK carries SND.NXT, the right edge of the window this side advertised.
    from_peer(
        &mut stack,
        &mut out,
        from(edge, start.wrapping_add(48), 0),
        &[],
    );
    stack.poll(&mut out);
    out.packets.clear();

    tokio::time::advance(Duration::from_secs(3)).await;
    stack.poll(&mut out);
    assert!(
        out.packets.iter().all(|p| segment(p).payload.is_empty()),
        "the acknowledged upload is not sent again"
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_retransmission_that_moves_the_ack_brings_its_window() {
    let mut stack = TcpStack::new(StackConfig::default());
    let mut out = Wire::default();
    let (local, remote) = addrs();
    let mut stream = stack.connect(local, remote, Congestion::Cubic).unwrap();
    stack.poll(&mut out);
    let start = segment(&out.packets.pop().unwrap()).seq.wrapping_add(1);
    let peer = u32::MAX - 2000;
    let from = |seq: u32, ack: u32, window: u16| TcpHeader {
        src: remote,
        dst: local,
        seq,
        ack,
        flags: FLAG_ACK,
        window,
    };
    from_peer(
        &mut stack,
        &mut out,
        TcpHeader {
            flags: FLAG_SYN | FLAG_ACK,
            ..from(peer.wrapping_sub(1), start, 8000)
        },
        &[],
    );
    stack.poll(&mut out);
    stream.write_all(&[7; 8000]).await.unwrap();
    stack.poll(&mut out);
    out.packets.clear();

    from_peer(
        &mut stack,
        &mut out,
        from(peer.wrapping_add(1000), start, 8000),
        &[1; 1000],
    );
    let closed = from(peer, start.wrapping_add(8000), 0);
    from_peer(&mut stack, &mut out, closed, &[1; 1000]);
    stream.write_all(&[9; 8000]).await.unwrap();
    stack.poll(&mut out);
    let beyond: Vec<_> = out
        .packets
        .iter()
        .map(|p| segment(p))
        .filter(|s| !s.payload.is_empty())
        .collect();
    assert!(beyond.is_empty(), "the window closed with that ACK");
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_window_of_a_syn_ack_is_not_scaled() {
    let mut stack = TcpStack::new(StackConfig::default());
    let mut out = Wire::default();
    let (local, remote) = addrs();
    let mut stream = stack.connect(local, remote, Congestion::Cubic).unwrap();
    stack.poll(&mut out);
    let start = segment(&out.packets.pop().unwrap()).seq.wrapping_add(1);
    let header = TcpHeader {
        src: remote,
        dst: local,
        seq: 1000,
        ack: start,
        flags: FLAG_SYN | FLAG_ACK,
        window: 2000,
    };
    let options = TcpOptions {
        mss: Some(1460),
        window_scale: Some(7),
        ..TcpOptions::default()
    };
    let mut packet = vec![0; 128];
    let len = emit_tcp(&mut packet, &header, &options, 0, L4Checksum::Full, |_| {
        Some(())
    })
    .unwrap();
    let Ok(Parsed::Packet(view)) = parse_packet(&packet[..len]) else {
        panic!("invalid SYN-ACK");
    };
    stack.input(view.src, view.dst, view.l4, &mut out, |_, _| Admit::Reject);
    stack.poll(&mut out);
    out.packets.clear();
    stream.write_all(&[7; 8000]).await.unwrap();
    stack.poll(&mut out);
    let sent: usize = out.packets.iter().map(|p| segment(p).payload.len()).sum();
    assert_eq!(
        sent, 2000,
        "RFC 7323 2.2: the SYN-ACK's window field is unscaled"
    );
}
