use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;

use concord_common::{
    Address, BoxRead, BoxWrite, Datagram, DialCx, PacketBuf, PacketSession, RecvBatch, SockOpts,
    recv_packet, send_packet,
};
use concord_platform::{UDP_BATCH, UdpBatch};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::node::{Egress, resolve_server};

const FRAME_LIMIT: usize = u16::MAX as usize;
const TCP_BUFFER: usize = 2 * (2 + FRAME_LIMIT);

/// The connection to the OpenVPN server, the sending side. UDP send errors drop the
/// datagram, as mihomo's datagram writer does; the reliable layer and ping-restart cover
/// the loss.
pub(super) enum Link {
    Udp {
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        batch: UdpBatch,
    },
    Session {
        session: Arc<dyn PacketSession>,
        peer: Address,
    },
    Tcp(tokio::sync::Mutex<BoxWrite>),
}

pub(super) enum Reader {
    Udp {
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        batch: Box<RecvBatch>,
        one: Vec<u8>,
    },
    Session {
        session: Arc<dyn PacketSession>,
    },
    Tcp {
        read: BoxRead,
        buf: Vec<u8>,
        start: usize,
        end: usize,
    },
}

pub(super) async fn open(
    cx: &DialCx<'_>,
    egress: &Egress,
    server: &Address,
    tcp: bool,
) -> io::Result<(Link, Reader)> {
    if tcp {
        let (read, write) = egress.dial(cx, server).await?.into_split();
        return Ok((
            Link::Tcp(tokio::sync::Mutex::new(write)),
            Reader::Tcp {
                read,
                buf: vec![0; TCP_BUFFER],
                start: 0,
                end: 0,
            },
        ));
    }
    let peer = resolve_server(cx, server, egress.version()).await?;
    if let Some(via) = egress.via() {
        let inner = cx.enter(egress.name())?;
        let session = cx
            .env
            .nodes
            .associate_via(via, &inner, &Address::from(peer))
            .await?;
        return Ok((
            Link::Session {
                session: session.clone(),
                peer: Address::from(peer),
            },
            Reader::Session { session },
        ));
    }
    let opts = SockOpts {
        tunnel_udp_buffers: true,
        ..egress.sock_opts(cx.env)
    };
    let socket = Arc::new(cx.env.sockets.bind_udp(peer.ip(), &opts)?);
    Ok((
        Link::Udp {
            socket: socket.clone(),
            peer,
            batch: UdpBatch::default(),
        },
        Reader::Udp {
            socket,
            peer,
            batch: Box::default(),
            one: Vec::new(),
        },
    ))
}

impl Link {
    pub(super) fn is_tcp(&self) -> bool {
        matches!(self, Link::Tcp(_))
    }

    pub(super) async fn send(&self, packet: &[u8]) -> io::Result<()> {
        self.send_all(std::slice::from_ref(&packet)).await
    }

    pub(super) async fn send_all<P: AsRef<[u8]>>(&self, packets: &[P]) -> io::Result<()> {
        match self {
            Link::Udp {
                socket,
                peer,
                batch,
            } => {
                if UdpBatch::SENDS && packets.len() > 1 {
                    send_batch(socket, *peer, batch, packets).await;
                } else {
                    for packet in packets {
                        let _ = socket.send_to(packet.as_ref(), *peer).await;
                    }
                }
                Ok(())
            }
            Link::Session { session, peer } => {
                for packet in packets {
                    let mut out = PacketBuf::with_headroom(session.headroom());
                    out.extend_from_slice(packet.as_ref());
                    send_packet(&**session, &mut out, peer).await?;
                }
                Ok(())
            }
            Link::Tcp(write) => {
                let mut frames =
                    Vec::with_capacity(packets.iter().map(|p| p.as_ref().len() + 2).sum());
                for packet in packets {
                    let packet = packet.as_ref();
                    let len = u16::try_from(packet.len()).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "OpenVPN TCP packet too large")
                    })?;
                    frames.extend_from_slice(&len.to_be_bytes());
                    frames.extend_from_slice(packet);
                }
                let mut write = write.lock().await;
                write.write_all(&frames).await?;
                write.flush().await
            }
        }
    }
}

async fn send_batch<P: AsRef<[u8]>>(
    socket: &UdpSocket,
    peer: SocketAddr,
    batch: &UdpBatch,
    packets: &[P],
) {
    let mut rest = packets;
    while !rest.is_empty() {
        let datagrams: Vec<Datagram<'_>> = rest
            .iter()
            .take(UDP_BATCH)
            .map(|packet| Datagram {
                payload: packet.as_ref(),
                dst: peer,
            })
            .collect();
        if socket.writable().await.is_err() {
            return;
        }
        match batch.send(socket, &datagrams) {
            Ok(sent) => rest = rest.get(sent.max(1)..).unwrap_or_default(),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => rest = rest.get(1..).unwrap_or_default(),
        }
    }
}

impl Reader {
    /// Waits for at least one packet from the server and hands each one now available to
    /// `each`. Datagrams from any other source are not the server's and are skipped.
    pub(super) async fn recv(&mut self, mut each: impl FnMut(&[u8])) -> io::Result<()> {
        match self {
            Reader::Udp {
                socket,
                peer,
                batch,
                one,
            } => {
                if UdpBatch::RECEIVES {
                    poll_fn(|cx| {
                        loop {
                            match socket.poll_recv_ready(cx) {
                                Poll::Ready(Ok(())) => match UdpBatch::recv(socket, batch) {
                                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                                    other => return Poll::Ready(other),
                                },
                                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                    })
                    .await?;
                    for (data, from) in batch.iter() {
                        if from == *peer {
                            each(data);
                        }
                    }
                    return Ok(());
                }
                one.resize(FRAME_LIMIT + 1, 0);
                loop {
                    match socket.recv_from(one).await {
                        Ok((len, from)) if from == *peer => {
                            each(one.get(..len).unwrap_or_default());
                            return Ok(());
                        }
                        Ok(_) => {}
                        // Windows reports an ICMP port unreachable for an earlier datagram as a read error.
                        Err(err) if err.kind() == io::ErrorKind::ConnectionReset => {}
                        Err(err) => return Err(err),
                    }
                }
            }
            Reader::Session { session } => {
                let (data, _) = recv_packet(&**session).await?;
                each(data.as_slice());
                Ok(())
            }
            Reader::Tcp {
                read,
                buf,
                start,
                end,
            } => loop {
                let mut delivered = false;
                while let Some((head, rest)) = buf
                    .get(*start..*end)
                    .and_then(<[u8]>::split_first_chunk::<2>)
                {
                    let len = usize::from(u16::from_be_bytes(*head));
                    if len == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "empty OpenVPN TCP packet",
                        ));
                    }
                    let Some(frame) = rest.get(..len) else {
                        break;
                    };
                    each(frame);
                    *start += 2 + len;
                    delivered = true;
                }
                if delivered {
                    return Ok(());
                }
                if *start > 0 {
                    buf.copy_within(*start..*end, 0);
                    *end -= *start;
                    *start = 0;
                }
                let read_len = read.read(buf.get_mut(*end..).unwrap_or_default()).await?;
                if read_len == 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                *end += read_len;
            },
        }
    }
}
