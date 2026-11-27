//! Mux.Cool, which a VMess or VLESS client opens with the mux command and other clients at
//! `v1.mux.cool`, served as sing-vmess's `HandleMuxConnection` serves it (`mux.go:22-387`):
//! each session the client opens is a TCP request or a UDP association of its own, and XUDP
//! is its UDP session.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use concord_common::serve::{InboundCx, Peer};
use concord_common::{Address, BoxStream, InboundInfo, Stream};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream, ReadBuf, ReadHalf,
    WriteHalf, split,
};
use tokio::sync::{Mutex as AsyncMutex, Semaphore, oneshot};

use super::flows;
use super::mux::Mux;
use super::packets;
use crate::addr_codec::{MAX_ADDR_LEN, VMESS};
use crate::uot::AddrFrames;
use crate::util::{invalid_data, lock};

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEP_ALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const OPTION_ERROR: u8 = 2;
const NETWORK_TCP: u8 = 1;
const NETWORK_UDP: u8 = 2;
/// One frame's data each way between the connection and a session's flow.
const PIPE: usize = 65535;
/// What the client's frames may hold between the connection and all its sessions' flows:
/// one frame with its datagram header, as sing-vmess's `recv` writes each frame into an
/// `io.Pipe` and waits for the flow to take it (`mux.go:225`).
const IN_FLIGHT: usize = PIPE + MAX_ADDR_LEN + 2;
/// The most of a flow's output one frame carries.
const CHUNK: usize = 32 * 1024;

type Writer = Arc<AsyncMutex<WriteHalf<BoxStream>>>;
type Sessions = Arc<Mutex<HashMap<u16, Session>>>;
type Pipe = Arc<AsyncMutex<WriteHalf<DuplexStream>>>;

struct Session {
    to: Delivery,
    /// Which session under its id this is, so that a pump ends only its own.
    generation: u64,
    /// Dropped with the session, which stops its pump.
    _ended: oneshot::Sender<()>,
}

/// Where a session's data from the client goes.
#[derive(Clone)]
struct Delivery {
    pipe: Pipe,
    /// Bytes in the pipe the flow has not read, which hold that much of [`IN_FLIGHT`].
    held: Arc<AtomicUsize>,
    network: u8,
    destination: Address,
}

/// Runs the connection until the client ends it. A session's flow sees its end when the
/// client ends the session or the connection; the client sees one when the flow stops
/// writing.
pub(super) async fn serve(
    stream: BoxStream,
    inbound: InboundInfo,
    peer: Peer,
    cx: Arc<InboundCx>,
    mux: Mux,
) {
    let (reader, writer) = split(stream);
    let mut conn = Conn {
        reader: BufReader::new(reader),
        writer: Arc::new(AsyncMutex::new(writer)),
        sessions: Arc::default(),
        budget: Arc::new(Semaphore::new(IN_FLIGHT)),
        generations: 0,
        inbound,
        peer,
        cx,
        mux,
    };
    let ended = conn.receive().await;
    lock(&conn.sessions).clear();
    if let Err(err) = ended {
        tracing::debug!("{}: mux.cool: {err}", conn.inbound.name);
    }
}

struct Conn {
    reader: BufReader<ReadHalf<BoxStream>>,
    writer: Writer,
    sessions: Sessions,
    budget: Arc<Semaphore>,
    generations: u64,
    inbound: InboundInfo,
    peer: Peer,
    cx: Arc<InboundCx>,
    mux: Mux,
}

impl Conn {
    /// `recv` (`mux.go:77-218`), frame by frame.
    async fn receive(&mut self) -> std::io::Result<()> {
        let mut meta = Vec::new();
        let mut data = Vec::new();
        loop {
            let len = match self.reader.read_u16().await {
                Ok(len) => usize::from(len),
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(err) => return Err(err),
            };
            if len < 4 {
                return Err(invalid_data("short mux.cool frame"));
            }
            let id = self.reader.read_u16().await?;
            let status = self.reader.read_u8().await?;
            let option = self.reader.read_u8().await?;
            meta.resize(len - 4, 0);
            self.reader.read_exact(&mut meta).await?;
            let (network, destination) = match meta.split_first() {
                None => (0, None),
                Some((&network, addr)) => {
                    let (addr, _) = VMESS
                        .parse(addr)?
                        .ok_or_else(|| invalid_data("short mux.cool address"))?;
                    (network, Some(addr))
                }
            };
            let session = match status {
                STATUS_NEW => self.open(id, network, destination.clone())?,
                STATUS_KEEP => {
                    let session = self.pipe_of(id);
                    if session.is_none() {
                        write(&self.writer, &close_frame(id, true)).await?;
                    }
                    session
                }
                STATUS_END => {
                    lock(&self.sessions).remove(&id);
                    None
                }
                STATUS_KEEP_ALIVE => None,
                _ => return Err(invalid_data("bad mux.cool session status")),
            };
            if option & OPTION_DATA == 0 {
                continue;
            }
            let len = usize::from(self.reader.read_u16().await?);
            data.resize(len, 0);
            self.reader.read_exact(&mut data).await?;
            let Some(to) = session else {
                continue;
            };
            if len == 0 {
                continue;
            }
            let delivered = match to.network {
                NETWORK_TCP => deliver(&self.budget, &to, &data).await,
                _ => {
                    let addr = destination.as_ref().unwrap_or(&to.destination);
                    let mut packet = vec![0; VMESS.len(addr)];
                    VMESS.write_into(addr, &mut packet)?;
                    packet.extend_from_slice(&(len as u16).to_be_bytes());
                    packet.extend_from_slice(&data);
                    deliver(&self.budget, &to, &packet).await
                }
            };
            if delivered.is_err() && lock(&self.sessions).remove(&id).is_some() {
                write(&self.writer, &close_frame(id, true)).await?;
            }
        }
    }

    /// A new session replaces one the client opened under the same id, as sing-vmess's
    /// map does.
    fn open(
        &mut self,
        id: u16,
        network: u8,
        destination: Option<Address>,
    ) -> std::io::Result<Option<Delivery>> {
        if network != NETWORK_TCP && network != NETWORK_UDP {
            return Err(invalid_data("bad mux.cool network"));
        }
        let destination =
            destination.ok_or_else(|| invalid_data("a mux.cool session without a destination"))?;
        let (near, far) = tokio::io::duplex(PIPE);
        let (far_read, far_write) = split(far);
        let pipe: Pipe = Arc::new(AsyncMutex::new(far_write));
        let held = Arc::new(AtomicUsize::new(0));
        let near = Metered {
            inner: Some(near),
            budget: self.budget.clone(),
            held: held.clone(),
        };
        let (ended_tx, ended) = oneshot::channel();
        let to = Delivery {
            pipe,
            held,
            network,
            destination: destination.clone(),
        };
        self.generations += 1;
        let generation = self.generations;
        let session = Session {
            to: to.clone(),
            generation,
            _ended: ended_tx,
        };
        lock(&self.sessions).insert(id, session);
        let pump = Pump {
            id,
            generation,
            far: far_read,
            writer: self.writer.clone(),
            sessions: self.sessions.clone(),
        };
        let inbound = self.inbound.clone();
        let cx = &self.cx;
        if network == NETWORK_TCP {
            cx.tasks.spawn(pump.tcp(ended));
            let mux = self.mux.nested();
            flows::tcp(
                Box::new(near),
                destination.clone(),
                inbound,
                self.peer,
                cx,
                &mux,
            );
        } else {
            cx.tasks.spawn(pump.udp(ended));
            let frames = AddrFrames(VMESS);
            let association = packets::serve(
                Box::new(near),
                frames,
                frames,
                destination.clone(),
                inbound,
                self.peer.src,
                cx.clone(),
            );
            cx.tasks.spawn(association);
        }
        Ok(Some(to))
    }

    fn pipe_of(&self, id: u16) -> Option<Delivery> {
        lock(&self.sessions)
            .get(&id)
            .map(|session| session.to.clone())
    }
}

/// Waits for room in [`IN_FLIGHT`] before it writes, so a flow that does not read holds the
/// whole connection, as in sing-vmess.
async fn deliver(budget: &Semaphore, to: &Delivery, bytes: &[u8]) -> io::Result<()> {
    let n = u32::try_from(bytes.len()).map_err(|_| invalid_data("mux.cool frame too long"))?;
    budget
        .acquire_many(n)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?
        .forget();
    to.held.fetch_add(bytes.len(), Ordering::AcqRel);
    let written = to.pipe.lock().await.write_all(bytes).await;
    if written.is_err() {
        budget.add_permits(to.held.swap(0, Ordering::AcqRel));
    }
    written
}

/// A session's end of its pipe, which gives the connection's budget back as the flow reads,
/// and what it left unread once it drops.
struct Metered<S = DuplexStream> {
    /// Taken on drop, so that the pipe is closed before what it holds is given back: a frame
    /// written in between would succeed and its budget would never return.
    inner: Option<S>,
    budget: Arc<Semaphore>,
    held: Arc<AtomicUsize>,
}

impl<S> Metered<S> {
    fn inner(&mut self) -> io::Result<Pin<&mut S>>
    where
        S: Unpin,
    {
        let inner = self.inner.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
        Ok(Pin::new(inner))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        ready!(this.inner()?.poll_read(cx, buf))?;
        let n = buf.filled().len() - before;
        if n > 0 {
            this.held.fetch_sub(n, Ordering::AcqRel);
            this.budget.add_permits(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().inner()?.poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().inner()?.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().inner()?.poll_shutdown(cx)
    }
}

impl<S> Drop for Metered<S> {
    fn drop(&mut self) {
        drop(self.inner.take());
        self.budget.add_permits(self.held.swap(0, Ordering::AcqRel));
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> Stream for Metered<S> {
    concord_common::stream_policy!(default: all);
}

/// What one session's flow writes, framed for the client.
struct Pump {
    id: u16,
    generation: u64,
    far: ReadHalf<DuplexStream>,
    writer: Writer,
    sessions: Sessions,
}

impl Pump {
    /// `writeFrame` (`mux.go:257-279`).
    async fn tcp(self, ended: oneshot::Receiver<()>) {
        let Pump {
            id,
            generation,
            mut far,
            writer,
            sessions,
        } = self;
        let [hi, lo] = id.to_be_bytes();
        let run = async {
            let mut chunk = vec![0; CHUNK];
            let mut frame = Vec::with_capacity(8 + CHUNK);
            loop {
                let data = match far.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => chunk.get(..n).unwrap_or_default(),
                };
                frame.clear();
                frame.extend_from_slice(&[0, 4, hi, lo, STATUS_KEEP, OPTION_DATA]);
                frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
                frame.extend_from_slice(data);
                if write(&writer, &frame).await.is_err() {
                    return;
                }
            }
        };
        finish(id, generation, &writer, &sessions, run, ended).await;
    }

    /// `writePacketFrame` (`mux.go:298-330`), from the frames `AddrFrames` encodes.
    async fn udp(self, ended: oneshot::Receiver<()>) {
        let Pump {
            id,
            generation,
            mut far,
            writer,
            sessions,
        } = self;
        let [hi, lo] = id.to_be_bytes();
        let run = async {
            let mut payload = Vec::new();
            loop {
                let Ok(to) = VMESS.read(&mut far).await else {
                    return;
                };
                let Ok(len) = far.read_u16().await else {
                    return;
                };
                payload.resize(usize::from(len), 0);
                if far.read_exact(&mut payload).await.is_err() {
                    return;
                }
                let mut addr = vec![0; VMESS.len(&to)];
                if VMESS.write_into(&to, &mut addr).is_err() {
                    return;
                }
                let Ok(meta) = u16::try_from(5 + addr.len()) else {
                    return;
                };
                let mut frame = meta.to_be_bytes().to_vec();
                frame.extend_from_slice(&[hi, lo, STATUS_KEEP, OPTION_DATA, NETWORK_UDP]);
                frame.extend_from_slice(&addr);
                frame.extend_from_slice(&len.to_be_bytes());
                frame.extend_from_slice(&payload);
                if write(&writer, &frame).await.is_err() {
                    return;
                }
            }
        };
        finish(id, generation, &writer, &sessions, run, ended).await;
    }
}

/// The session ends with whichever comes first: the flow stops writing, which ends it for
/// the client too (`serverMuxConn.Close`), or the client or the connection ends it.
async fn finish(
    id: u16,
    generation: u64,
    writer: &Writer,
    sessions: &Sessions,
    run: impl Future<Output = ()>,
    ended: oneshot::Receiver<()>,
) {
    tokio::select! {
        () = run => {}
        _ = ended => return,
    }
    let was_open = {
        let mut sessions = lock(sessions);
        let own = sessions
            .get(&id)
            .is_some_and(|session| session.generation == generation);
        if own {
            sessions.remove(&id);
        }
        own
    };
    if was_open {
        let _ = write(writer, &close_frame(id, false)).await;
    }
}

async fn write(writer: &Writer, frame: &[u8]) -> std::io::Result<()> {
    let mut writer = writer.lock().await;
    writer.write_all(frame).await?;
    writer.flush().await
}

/// `writeCloseFrame` (`mux.go:368-387`).
fn close_frame(id: u16, error: bool) -> [u8; 6] {
    let [hi, lo] = id.to_be_bytes();
    let option = if error { OPTION_ERROR } else { 0 };
    [0, 4, hi, lo, STATUS_END, option]
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;

    use concord_common::packet::UdpPayload;
    use concord_common::{FlowHandler, FlowMeta, InboundKind, Tasks, UdpFlow, UdpReply};
    use tokio::io::DuplexStream;

    use super::*;

    const ECHO: u16 = 7;
    const WATCH: u16 = 8;
    const HOLD: u16 = 9;

    /// Echoes a TCP flow to port 7, counts the flows to port 8 that read to their end, keeps
    /// those to port 9 unread, and sends any other `bye` before closing it; answers each
    /// datagram with itself, from where it was sent.
    #[derive(Clone, Default)]
    struct Echo {
        watched: Arc<AtomicUsize>,
        held: Arc<Mutex<Vec<BoxStream>>>,
    }

    impl FlowHandler for Echo {
        fn handle_tcp(&self, meta: FlowMeta, mut stream: BoxStream) {
            let echo = self.clone();
            tokio::spawn(async move {
                match meta.dst.port() {
                    ECHO => {
                        let (mut read, mut write) = split(stream);
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                    }
                    WATCH => {
                        let _ = stream.read_to_end(&mut Vec::new()).await;
                        echo.watched.fetch_add(1, Ordering::SeqCst);
                    }
                    HOLD => lock(&echo.held).push(stream),
                    _ => {
                        let _ = stream.write_all(b"bye").await;
                    }
                }
            });
        }

        fn handle_udp(
            &self,
            flow: UdpFlow<'_>,
            payload: UdpPayload<'_>,
            reply: &Arc<dyn UdpReply>,
        ) {
            let (reply, data, from) = (reply.clone(), payload.as_slice().to_vec(), flow.dst);
            tokio::spawn(async move {
                let _ = poll_fn(|cx| reply.poll_write_back(cx, &data, &from)).await;
            });
        }
    }

    fn start() -> DuplexStream {
        start_with(&Echo::default())
    }

    fn start_with(echo: &Echo) -> DuplexStream {
        let cx = Arc::new(InboundCx {
            name: "in".into(),
            special: None,
            handler: Arc::new(echo.clone()),
            tasks: Tasks::default(),
        });
        let peer = Peer {
            src: "10.0.0.2:4000".parse().unwrap(),
            local: "10.0.0.1:443".parse().unwrap(),
        };
        let inbound = cx.inbound(InboundKind::Vmess, peer.local, None);
        let (near, far) = tokio::io::duplex(1 << 16);
        let mux = Mux::new(&Arc::default());
        tokio::spawn(serve(Box::new(far), inbound, peer, cx.clone(), mux));
        near
    }

    fn frame(id: u16, status: u8, network: Option<(u8, &Address)>, data: Option<&[u8]>) -> Vec<u8> {
        let mut meta = id.to_be_bytes().to_vec();
        let option = if data.is_some() { OPTION_DATA } else { 0 };
        meta.extend_from_slice(&[status, option]);
        if let Some((network, to)) = network {
            meta.push(network);
            let mut addr = vec![0; VMESS.len(to)];
            VMESS.write_into(to, &mut addr).unwrap();
            meta.extend_from_slice(&addr);
        }
        let mut out = (meta.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&meta);
        if let Some(data) = data {
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    #[derive(Debug, PartialEq)]
    struct Frame {
        id: u16,
        status: u8,
        option: u8,
        to: Option<Address>,
        data: Vec<u8>,
    }

    async fn next(conn: &mut DuplexStream) -> Frame {
        let len = usize::from(conn.read_u16().await.unwrap());
        let mut meta = vec![0; len];
        conn.read_exact(&mut meta).await.unwrap();
        let to = meta.get(5..).filter(|addr| !addr.is_empty()).map(|addr| {
            assert_eq!(meta[4], NETWORK_UDP);
            VMESS.parse(addr).unwrap().unwrap().0
        });
        let mut data = Vec::new();
        if meta[3] & OPTION_DATA != 0 {
            data.resize(usize::from(conn.read_u16().await.unwrap()), 0);
            conn.read_exact(&mut data).await.unwrap();
        }
        Frame {
            id: u16::from_be_bytes([meta[0], meta[1]]),
            status: meta[2],
            option: meta[3],
            to,
            data,
        }
    }

    fn keep(id: u16, to: Option<Address>, data: &[u8]) -> Frame {
        Frame {
            id,
            status: STATUS_KEEP,
            option: OPTION_DATA,
            to,
            data: data.to_vec(),
        }
    }

    fn end(id: u16, option: u8) -> Frame {
        Frame {
            id,
            status: STATUS_END,
            option,
            to: None,
            data: Vec::new(),
        }
    }

    #[tokio::test]
    async fn tcp_sessions_of_one_connection_carry_their_own_bytes() {
        let mut conn = start();
        let echo = Address::new("example.com", ECHO);
        for (id, data) in [(1, &b"one"[..]), (2, b"two")] {
            let opening = frame(id, STATUS_NEW, Some((NETWORK_TCP, &echo)), Some(data));
            conn.write_all(&opening).await.unwrap();
            assert_eq!(next(&mut conn).await, keep(id, None, data));
        }
        conn.write_all(&frame(1, STATUS_END, None, None))
            .await
            .unwrap();
        conn.write_all(&frame(2, STATUS_KEEP, None, Some(b"again")))
            .await
            .unwrap();
        assert_eq!(next(&mut conn).await, keep(2, None, b"again"));
    }

    #[tokio::test]
    async fn a_flow_that_stops_writing_ends_its_session_for_the_client() {
        let mut conn = start();
        let to = Address::new("example.com", 80);
        conn.write_all(&frame(5, STATUS_NEW, Some((NETWORK_TCP, &to)), None))
            .await
            .unwrap();
        assert_eq!(next(&mut conn).await, keep(5, None, b"bye"));
        assert_eq!(next(&mut conn).await, end(5, 0));
    }

    #[tokio::test]
    async fn an_xudp_session_answers_from_each_datagrams_destination() {
        let mut conn = start();
        let (first, second) = (Address::new("8.8.8.8", 53), Address::new("1.1.1.1", 53));
        let mut opening = frame(0, STATUS_NEW, Some((NETWORK_UDP, &first)), Some(b"q1"));
        let global_id = [9u8; 8];
        let meta_end = 2 + usize::from(u16::from_be_bytes([opening[0], opening[1]]));
        opening.splice(meta_end..meta_end, global_id);
        let meta_len = (meta_end - 2 + global_id.len()) as u16;
        opening[..2].copy_from_slice(&meta_len.to_be_bytes());
        conn.write_all(&opening).await.unwrap();
        assert_eq!(next(&mut conn).await, keep(0, Some(first), b"q1"));

        let other = frame(0, STATUS_KEEP, Some((NETWORK_UDP, &second)), Some(b"q2"));
        conn.write_all(&other).await.unwrap();
        assert_eq!(next(&mut conn).await, keep(0, Some(second), b"q2"));
    }

    #[tokio::test]
    async fn data_for_a_session_never_opened_is_answered_with_an_error_end() {
        let mut conn = start();
        conn.write_all(&frame(9, STATUS_KEEP, None, Some(b"lost")))
            .await
            .unwrap();
        assert_eq!(next(&mut conn).await, end(9, OPTION_ERROR));

        let echo = Address::new("example.com", ECHO);
        let opening = frame(3, STATUS_NEW, Some((NETWORK_TCP, &echo)), Some(b"still"));
        conn.write_all(&opening).await.unwrap();
        assert_eq!(next(&mut conn).await, keep(3, None, b"still"));
    }

    #[tokio::test]
    async fn a_session_that_does_not_read_holds_the_connection_at_one_frame() {
        let echo = Echo::default();
        let mut conn = start_with(&echo);
        let hold = Address::new("example.com", HOLD);
        let chunk = vec![1u8; 40_000];
        for id in [1, 2] {
            let opening = frame(id, STATUS_NEW, Some((NETWORK_TCP, &hold)), Some(&chunk));
            conn.write_all(&opening).await.unwrap();
        }
        let echoed = Address::new("example.com", ECHO);
        conn.write_all(&frame(
            3,
            STATUS_NEW,
            Some((NETWORK_TCP, &echoed)),
            Some(b"ping"),
        ))
        .await
        .unwrap();
        let early = tokio::time::timeout(std::time::Duration::from_millis(300), next(&mut conn));
        assert!(early.await.is_err(), "a second frame passed the unread one");
        lock(&echo.held).clear();
        let mut frames = Vec::new();
        while !frames.contains(&keep(3, None, b"ping")) {
            frames.push(next(&mut conn).await);
        }
    }

    #[tokio::test]
    async fn a_session_opened_again_under_its_id_replaces_the_old_one() {
        let mut conn = start();
        let echoed = Address::new("example.com", ECHO);
        for data in [&b"a"[..], b"b"] {
            let opening = frame(1, STATUS_NEW, Some((NETWORK_TCP, &echoed)), Some(data));
            conn.write_all(&opening).await.unwrap();
            assert_eq!(next(&mut conn).await, keep(1, None, data));
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        conn.write_all(&frame(1, STATUS_KEEP, None, Some(b"c")))
            .await
            .unwrap();
        assert_eq!(next(&mut conn).await, keep(1, None, b"c"));
    }

    #[tokio::test]
    async fn the_end_of_the_connection_ends_every_session() {
        let echo = Echo::default();
        let mut conn = start_with(&echo);
        let watched = Address::new("example.com", WATCH);
        for id in [1, 2] {
            conn.write_all(&frame(id, STATUS_NEW, Some((NETWORK_TCP, &watched)), None))
                .await
                .unwrap();
        }
        conn.shutdown().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while echo.watched.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a session outlived its connection");
    }

    fn session(generation: u64) -> Session {
        let (_near, far) = tokio::io::duplex(16);
        let (_read, write) = split(far);
        let (ended, _) = oneshot::channel();
        Session {
            to: Delivery {
                pipe: Arc::new(AsyncMutex::new(write)),
                held: Arc::default(),
                network: NETWORK_TCP,
                destination: Address::new("example.com", ECHO),
            },
            generation,
            _ended: ended,
        }
    }

    #[tokio::test]
    async fn a_pump_that_ends_leaves_a_newer_session_under_its_id() {
        let sessions: Sessions = Arc::default();
        lock(&sessions).insert(1, session(2));
        let (mut client, server) = tokio::io::duplex(64);
        let (read, write) = split(Box::new(server) as BoxStream);
        let writer: Writer = Arc::new(AsyncMutex::new(write));
        let (_alive, ended) = oneshot::channel();
        finish(1, 1, &writer, &sessions, async {}, ended).await;
        assert!(lock(&sessions).get(&1).is_some_and(|s| s.generation == 2));
        drop((read, writer));
        let mut sent = Vec::new();
        client.read_to_end(&mut sent).await.unwrap();
        assert!(sent.is_empty(), "{sent:?}");
    }

    /// Stands for a frame the receive loop writes while a session's pipe closes: what the
    /// session holds grows as the pipe drops.
    struct LateFrame {
        held: Arc<AtomicUsize>,
        len: usize,
    }

    impl Drop for LateFrame {
        fn drop(&mut self) {
            self.held.fetch_add(self.len, Ordering::AcqRel);
        }
    }

    #[test]
    fn a_frame_written_as_its_session_drops_gives_its_budget_back() {
        let budget = Arc::new(Semaphore::new(IN_FLIGHT));
        let held = Arc::new(AtomicUsize::new(0));
        let len = 1000;
        budget.try_acquire_many(1000).unwrap().forget();
        let late = LateFrame {
            held: held.clone(),
            len,
        };
        drop(Metered {
            inner: Some(late),
            budget: budget.clone(),
            held,
        });
        assert_eq!(budget.available_permits(), IN_FLIGHT);
    }
}
