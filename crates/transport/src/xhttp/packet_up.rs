use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::task::AtomicWaker;
use tokio::io::AsyncWrite;
use tokio::sync::Notify;

use super::config::Range;
use super::request::RequestFactory;
use super::transport::Lease;

#[derive(Default)]
struct State {
    buf: Vec<u8>,
    failure: Option<(io::ErrorKind, String)>,
    closed: bool,
    posting: bool,
}

struct Shared {
    state: Mutex<State>,
    data: Notify,
    close: Notify,
    space: AtomicWaker,
    max_bytes: usize,
}

struct Launcher {
    factory: Arc<RequestFactory>,
    transport: Lease,
    session: String,
    interval: Range,
    tasks: concord_common::Tasks,
}

fn lock(shared: &Shared) -> MutexGuard<'_, State> {
    concord_common::sync::lock(&shared.state)
}

/// The uplink of `packet-up`: bytes pile up for at least the minimum interval and
/// leave as numbered POSTs of at most `max_bytes`.
///
/// The upload task starts lazily on the first non-empty write, matching mihomo's
/// `DialPacketUp` / `PacketUpWriter.Write` (`transport/xhttp/client.go:595-607, 67-69`),
/// and `poll_shutdown` cancels any pending interval wait to flush buffered bytes
/// immediately, matching `PacketUpWriter.Close` (`transport/xhttp/client.go:89-101, 143-156`).
pub(crate) struct PacketUp {
    shared: Arc<Shared>,
    launcher: Option<Launcher>,
}

impl PacketUp {
    pub fn start(
        factory: Arc<RequestFactory>,
        transport: Lease,
        session: String,
        max_bytes: usize,
        interval: Range,
        tasks: &concord_common::Tasks,
    ) -> PacketUp {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            data: Notify::new(),
            close: Notify::new(),
            space: AtomicWaker::new(),
            max_bytes,
        });
        PacketUp {
            shared,
            launcher: Some(Launcher {
                factory,
                transport,
                session,
                interval,
                tasks: tasks.clone(),
            }),
        }
    }
}

async fn upload_loop(
    shared: Arc<Shared>,
    factory: Arc<RequestFactory>,
    transport: Lease,
    session: String,
    interval: Range,
) {
    let mut seq: u64 = 0;
    loop {
        let closing = loop {
            let notified = shared.data.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let state = lock(&shared);
                if !state.buf.is_empty() {
                    break state.closed;
                }
                if state.closed {
                    return;
                }
            }
            notified.await;
        };
        if !closing {
            let wait = Duration::from_millis(interval.rand() as u64);
            if !wait.is_zero() {
                let close_wait = shared.close.notified();
                tokio::pin!(close_wait);
                close_wait.as_mut().enable();
                if !lock(&shared).closed {
                    tokio::select! {
                        biased;
                        () = close_wait => {}
                        () = tokio::time::sleep(wait) => {}
                    }
                }
            }
        }
        let payload = {
            let mut state = lock(&shared);
            if state.buf.is_empty() {
                if state.closed {
                    return;
                }
                continue;
            }
            state.posting = true;
            std::mem::take(&mut state.buf)
        };
        shared.space.wake();
        let outcome = match factory.packet_request(&session, seq, &payload) {
            Ok((request, body)) => match transport.fixed(&request, body).await {
                Ok(200) => Ok(()),
                Ok(status) => Err((
                    io::ErrorKind::Other,
                    format!("xhttp packet-up bad status: {status}"),
                )),
                Err(err) => Err((err.kind(), err.to_string())),
            },
            Err(err) => Err((err.kind(), err.to_string())),
        };
        seq += 1;
        let mut state = lock(&shared);
        state.posting = false;
        if let Err(failure) = outcome {
            state.failure = Some(failure);
            state.buf.clear();
            drop(state);
            shared.space.wake();
            return;
        }
        drop(state);
        shared.space.wake();
    }
}

impl AsyncWrite for PacketUp {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let shared = &this.shared;
        let mut state = lock(shared);
        if let Some((kind, message)) = &state.failure {
            return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
        }
        if state.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let room = shared.max_bytes.saturating_sub(state.buf.len());
        if room == 0 {
            shared.space.register(cx.waker());
            return Poll::Pending;
        }
        let take = data.len().min(room);
        let Some(chunk) = data.get(..take).filter(|chunk| !chunk.is_empty()) else {
            return Poll::Ready(Ok(0));
        };
        state.buf.extend_from_slice(chunk);
        drop(state);
        if let Some(launcher) = this.launcher.take() {
            launcher.tasks.spawn(upload_loop(
                shared.clone(),
                launcher.factory,
                launcher.transport,
                launcher.session,
                launcher.interval,
            ));
        } else {
            shared.data.notify_one();
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let shared = &this.shared;
        let mut state = lock(shared);
        if let Some((kind, message)) = &state.failure {
            return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
        }
        state.closed = true;
        if state.buf.is_empty() && !state.posting {
            drop(state);
            this.launcher = None;
            return Poll::Ready(Ok(()));
        }
        shared.space.register(cx.waker());
        drop(state);
        shared.data.notify_one();
        shared.close.notify_waiters();
        Poll::Pending
    }
}

impl Drop for PacketUp {
    fn drop(&mut self) {
        lock(&self.shared).closed = true;
        self.shared.data.notify_one();
        self.shared.close.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::DialFn;
    use crate::xhttp::browser::Browser;
    use crate::xhttp::config::{Settings, XhttpOptions};
    use crate::xhttp::transport::Transport;

    fn test_packet_up(interval_ms: usize) -> PacketUp {
        let opts = XhttpOptions {
            host: "cdn.example.com".into(),
            path: "/xh".into(),
            mode: "packet-up".into(),
            ..XhttpOptions::default()
        };
        let settings = Settings::resolve(&opts).unwrap();
        let factory = Arc::new(RequestFactory::new(opts, settings, Browser::new()));
        let dial: DialFn = Arc::new(|| Box::pin(async { Err(io::Error::other("unused")) }));
        let tasks = concord_common::Tasks::default();
        let transport = Lease::owned(Transport::new(false, dial, 0, tasks.clone()));
        PacketUp::start(
            factory,
            transport,
            "session-1".into(),
            1024,
            Range {
                min: interval_ms,
                max: interval_ms,
            },
            &tasks,
        )
    }

    #[tokio::test]
    async fn uploader_does_not_start_until_first_non_empty_write() {
        let mut idle = test_packet_up(30);
        assert!(idle.launcher.is_some());
        assert_eq!(idle.write(&[]).await.unwrap(), 0);
        assert!(idle.launcher.is_some());
        idle.shutdown().await.unwrap();
        assert!(idle.launcher.is_none());

        let mut active = test_packet_up(5_000);
        assert!(active.launcher.is_some());
        assert_eq!(active.write(b"hi").await.unwrap(), 2);
        assert!(active.launcher.is_none());
    }
}
