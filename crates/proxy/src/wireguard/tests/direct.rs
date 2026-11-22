use std::future::poll_fn;

use tokio::net::{TcpListener, TcpStream};

use super::*;

#[tokio::test]
async fn a_stream_keeps_an_attached_socket_through_duplex_half_close() {
    let (_server, outbound) = setup(json!({})).await;
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let target = Address::new(&SERVER_TUNNEL_IP.to_string(), 7);
    let mut stream = tokio::time::timeout(Duration::from_secs(10), outbound.connect(&cx, &target))
        .await
        .expect("connect timed out")
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, accepted) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept(),
    );
    let mut client = client.unwrap();
    let (socket, _) = accepted.unwrap();
    let mut attached = stream
        .direct()
        .expect("WireGuard must preserve the inner stream's direct I/O")
        .attach_owned(&mut Some(socket.into()))
        .expect("an established stream can take a socket");
    drop(outbound);

    let data = pattern(2 << 20);
    let (mut read, mut write) = client.split();
    let sender = async {
        write.write_all(&data).await.unwrap();
        write.shutdown().await.unwrap();
    };
    let receiver = async {
        let mut received = Vec::new();
        read.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, data);
    };
    let (_, _, done) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(sender, receiver, poll_fn(|cx| attached.poll_done(cx)))
    })
    .await
    .expect("attached duplex echo timed out");
    done.unwrap();
    let bytes = u64::try_from(data.len()).unwrap();
    assert_eq!(attached.moved(), (bytes, bytes));
    drop(attached);
    drop(stream);
}
