use std::io;

use concord_common::{BoxStream, Tasks};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use super::padding::padding_conn;
use super::smux::SmuxSession;
use super::wire::server_stream;
use super::yamux::YamuxSession;
use super::{MuxProtocol, h2mux};
use crate::http1::invalid;

/// Serves one sing-mux session, as sing-mux's `Service.NewConnection` (`server.go:52-85`):
/// reads the client's session request, then hands on every stream the client opens, each
/// answering with the success status before its first byte. `padding` refuses a client
/// that does not pad. Returns once the session ends.
pub async fn serve_session(
    mut conn: BoxStream,
    padding: bool,
    tasks: &Tasks,
    on_stream: &(dyn Fn(BoxStream) + Send + Sync),
) -> io::Result<()> {
    let (protocol, padded) = read_request(&mut conn).await?;
    if padded {
        conn = padding_conn(conn);
    } else if padding {
        return Err(invalid("non-padded connection rejected"));
    }
    let hand_on = |stream| on_stream(server_stream(stream));
    match MuxProtocol::from_id(protocol) {
        Some(MuxProtocol::Smux) => {
            let (_session, accepted) = SmuxSession::server(conn, tasks);
            take(accepted, &hand_on).await;
        }
        Some(MuxProtocol::Yamux) => {
            let (_session, accepted) = YamuxSession::server(conn, tasks);
            take(accepted, &hand_on).await;
        }
        Some(MuxProtocol::H2Mux) => h2mux::serve(conn, &hand_on).await,
        None => return Err(invalid(format!("unexpected protocol {protocol}"))),
    }
    Ok(())
}

async fn take(mut accepted: mpsc::Receiver<BoxStream>, hand_on: &(dyn Fn(BoxStream) + Sync)) {
    while let Some(stream) = accepted.recv().await {
        hand_on(stream);
    }
}

/// `ReadRequest` (`protocol.go:38-73`): the version, the protocol and, from version 1,
/// whether the client pads, with the padding it sent first.
async fn read_request(conn: &mut BoxStream) -> io::Result<(u8, bool)> {
    let version = conn.read_u8().await?;
    if version > 1 {
        return Err(invalid(format!("unsupported version: {version}")));
    }
    let protocol = conn.read_u8().await?;
    if version == 0 || conn.read_u8().await? == 0 {
        return Ok((protocol, false));
    }
    let skip = conn.read_u16().await?;
    let skipped = tokio::io::copy(
        &mut (&mut *conn).take(u64::from(skip)),
        &mut tokio::io::sink(),
    )
    .await?;
    if skipped < u64::from(skip) {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok((protocol, true))
}
