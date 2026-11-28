//! The host side of the desktop core's control connection: the token handshake
//! of `crates/ipc` and its length-prefixed JSON-RPC frames. It is restated here so
//! the harness does not link the engine; `tests::speaks_concord_ipc` holds the
//! two together.

use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::sync::mpsc;

const CALL_TIMEOUT: Duration = Duration::from_secs(120);
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(20);
const LABEL: &[u8] = b"concord-ipc/1";
const NONCE_LEN: usize = 16;
const PROOF_LEN: usize = 32;
const MAX_MESSAGE: usize = 64 << 20;

pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Stream for T {}

/// A 32-digit lowercase hex session token, as `concord` reads it from stdin.
pub fn token() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

fn proof(token: &str, role: u8, initiator: &[u8], responder: &[u8]) -> [u8; PROOF_LEN] {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(token.as_bytes()).expect("HMAC takes any key");
    mac.update(LABEL);
    mac.update(&[role]);
    mac.update(initiator);
    mac.update(responder);
    mac.finalize().into_bytes().into()
}

async fn send_frame<S: AsyncWrite + Unpin>(io: &mut S, body: &[u8]) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(body);
    io.write_all(&frame).await?;
    io.flush().await
}

async fn recv_frame<S: AsyncRead + Unpin>(io: &mut S) -> std::io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    match io.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_MESSAGE {
        return Err(std::io::Error::other(format!("frame of {len} bytes")));
    }
    let mut body = vec![0u8; len];
    io.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// The listening side of the handshake: read the core's nonce, prove the token
/// with ours, then check the core's proof.
pub async fn respond<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    token: &str,
) -> Result<(), String> {
    let work = async {
        let theirs = recv_frame(io)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("closed")?;
        if theirs.len() != NONCE_LEN {
            return Err("malformed nonce".to_string());
        }
        let ours: [u8; NONCE_LEN] = rand::random();
        let mut reply = ours.to_vec();
        reply.extend_from_slice(&proof(token, 2, &theirs, &ours));
        send_frame(io, &reply).await.map_err(|e| e.to_string())?;
        let claimed = recv_frame(io)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("closed")?;
        if claimed.as_slice() != proof(token, 1, &theirs, &ours) {
            return Err("the core does not know the token".to_string());
        }
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(5), work)
        .await
        .map_err(|_| "handshake timed out".to_string())?
}

pub struct Control {
    writer: WriteHalf<Box<dyn Stream>>,
    responses: mpsc::UnboundedReceiver<Value>,
    reader: tokio::task::JoinHandle<()>,
    next: u64,
}

impl Drop for Control {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl Control {
    pub async fn open(mut stream: Box<dyn Stream>, token: &str) -> Result<Control, String> {
        respond(&mut stream, token)
            .await
            .map_err(|e| format!("control handshake: {e}"))?;
        let (mut reader, writer) = tokio::io::split(stream);
        let (feed, responses) = mpsc::unbounded_channel();
        let reader = tokio::spawn(async move {
            while let Ok(Some(message)) = recv_frame(&mut reader).await {
                if let Ok(value) = serde_json::from_slice::<Value>(&message)
                    && value.get("id").is_some()
                    && feed.send(value).is_err()
                {
                    return;
                }
            }
        });
        let mut control = Control {
            writer,
            responses,
            reader,
            next: 0,
        };
        control
            .call(
                "core.hello",
                json!({"protocol": {"min": 1, "max": 1}, "client": {"name": "concord-bench", "version": env!("CARGO_PKG_VERSION")}}),
            )
            .await?;
        Ok(control)
    }

    pub async fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.next += 1;
        let id = self.next;
        let message = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        send_frame(
            &mut self.writer,
            &serde_json::to_vec(&message).map_err(|e| e.to_string())?,
        )
        .await
        .map_err(|_| format!("{method}: control connection closed"))?;
        let wait = async {
            loop {
                let response = self.responses.recv().await?;
                if response["id"] == json!(id) {
                    return Some(response);
                }
            }
        };
        let response = tokio::time::timeout(CALL_TIMEOUT, wait)
            .await
            .map_err(|_| format!("{method}: no answer in {CALL_TIMEOUT:?}"))?
            .ok_or_else(|| format!("{method}: control connection closed"))?;
        match response.get("error") {
            Some(error) => Err(format!("{method}: {error}")),
            None => Ok(response["result"].clone()),
        }
    }
}

/// Where the core dials back: a Unix socket, a named pipe on Windows, or on
/// Android a loopback TCP port, since SELinux keeps the shell user from creating
/// socket files. `concord` reads an all-digit address as such a port.
pub struct Endpoint {
    pub address: String,
    listener: Listener,
}

enum Listener {
    #[cfg(all(unix, not(target_os = "android")))]
    Unix(tokio::net::UnixListener),
    #[cfg(target_os = "android")]
    Tcp(tokio::net::TcpListener),
    #[cfg(windows)]
    Pipe(tokio::net::windows::named_pipe::NamedPipeServer),
}

impl Endpoint {
    pub fn bind() -> Result<Endpoint, String> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let tag = format!(
            "cb{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        #[cfg(all(unix, not(target_os = "android")))]
        {
            // The home directory can be deeper than the 104 bytes a socket path may take on macOS.
            let path = std::env::temp_dir().join(format!("{tag}.sock"));
            let _ = std::fs::remove_file(&path);
            let listener = tokio::net::UnixListener::bind(&path)
                .map_err(|e| format!("bind {}: {e}", path.display()))?;
            Ok(Endpoint {
                address: path.to_string_lossy().into_owned(),
                listener: Listener::Unix(listener),
            })
        }
        #[cfg(target_os = "android")]
        {
            let _ = tag;
            let std = std::net::TcpListener::bind(("127.0.0.1", 0))
                .map_err(|e| format!("bind control port: {e}"))?;
            std.set_nonblocking(true).map_err(|e| e.to_string())?;
            let port = std.local_addr().map_err(|e| e.to_string())?.port();
            let listener = tokio::net::TcpListener::from_std(std).map_err(|e| e.to_string())?;
            Ok(Endpoint {
                address: port.to_string(),
                listener: Listener::Tcp(listener),
            })
        }
        #[cfg(windows)]
        {
            let address = format!(r"\\.\pipe\concord-bench-{tag}");
            let pipe = tokio::net::windows::named_pipe::ServerOptions::new()
                .first_pipe_instance(true)
                .create(&address)
                .map_err(|e| format!("pipe {address}: {e}"))?;
            Ok(Endpoint {
                address,
                listener: Listener::Pipe(pipe),
            })
        }
    }

    pub async fn accept(self) -> Result<Box<dyn Stream>, String> {
        let address = self.address;
        let accepted = async move {
            match self.listener {
                #[cfg(all(unix, not(target_os = "android")))]
                Listener::Unix(listener) => {
                    let (stream, _) = listener
                        .accept()
                        .await
                        .map_err(|e| format!("accept: {e}"))?;
                    let _ = std::fs::remove_file(&address);
                    Ok::<Box<dyn Stream>, String>(Box::new(stream))
                }
                #[cfg(target_os = "android")]
                Listener::Tcp(listener) => {
                    let _ = address;
                    let (stream, _) = listener
                        .accept()
                        .await
                        .map_err(|e| format!("accept: {e}"))?;
                    Ok::<Box<dyn Stream>, String>(Box::new(stream))
                }
                #[cfg(windows)]
                Listener::Pipe(pipe) => {
                    let _ = address;
                    pipe.connect()
                        .await
                        .map_err(|e| format!("pipe connect: {e}"))?;
                    Ok::<Box<dyn Stream>, String>(Box::new(pipe))
                }
            }
        };
        tokio::time::timeout(ACCEPT_TIMEOUT, accepted)
            .await
            .map_err(|_| "the core never dialled the control endpoint".to_string())?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn speaks_concord_ipc() {
        let text = token();
        let shared = concord_ipc::Token::parse(&text).unwrap();
        let (mut host, mut core) = tokio::io::duplex(4096);
        let core_side =
            tokio::spawn(async move { concord_ipc::initiate(&mut core, &shared).await.is_ok() });
        respond(&mut host, &text).await.unwrap();
        assert!(core_side.await.unwrap());
    }

    #[tokio::test]
    async fn dropping_the_control_ends_the_connection_so_the_core_exits() {
        let text = token();
        let shared = concord_ipc::Token::parse(&text).unwrap();
        let (host, mut core) = tokio::io::duplex(4096);
        let core_side = tokio::spawn(async move {
            concord_ipc::initiate(&mut core, &shared).await.unwrap();
            recv_frame(&mut core).await.unwrap().unwrap();
            let reply = json!({"jsonrpc": "2.0", "id": 1, "result": {}});
            send_frame(&mut core, &serde_json::to_vec(&reply).unwrap())
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), recv_frame(&mut core)).await
        });
        let control = Control::open(Box::new(host), &text).await.unwrap();
        drop(control);
        assert!(matches!(core_side.await.unwrap(), Ok(Ok(None))));
    }

    #[tokio::test]
    async fn a_wrong_token_is_refused() {
        let shared = concord_ipc::Token::parse(&token()).unwrap();
        let (mut host, mut core) = tokio::io::duplex(4096);
        tokio::spawn(async move { concord_ipc::initiate(&mut core, &shared).await });
        assert!(respond(&mut host, &token()).await.is_err());
    }
}
