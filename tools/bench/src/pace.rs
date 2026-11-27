//! A fixed rate for a bulk flow: the origin's downloads under `--origin-rate`, the client's uploads under
//! `--client-rate`.

use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use crate::origin::CHUNK;

/// Paces a flow at a fixed rate. A deadline in the past is not waited for, so the flow catches up on what
/// a coarse timer made it miss, up to `CATCH_UP` of the rate.
struct Pace {
    per_chunk: Duration,
    next: Instant,
}

const CATCH_UP: Duration = Duration::from_millis(10);

impl Pace {
    fn new(mbit: f64, now: Instant) -> Pace {
        Pace {
            per_chunk: Duration::from_secs_f64(CHUNK as f64 * 8.0 / (mbit * 1e6)),
            next: now,
        }
    }

    /// When the chunk after the one just written may go out.
    fn after_chunk(&mut self, now: Instant) -> Instant {
        if let Some(floor) = now.checked_sub(CATCH_UP) {
            self.next = self.next.max(floor);
        }
        self.next += self.per_chunk;
        self.next
    }
}

/// Writes `CHUNK`s of `byte` until the writer fails. Without a rate it only writes.
pub async fn send_chunks<W: AsyncWrite + Unpin>(
    write: &mut W,
    byte: u8,
    rate_mbit: Option<f64>,
) -> std::io::Result<()> {
    let chunk = vec![byte; CHUNK];
    let mut pace = rate_mbit.map(|mbit| Pace::new(mbit, Instant::now()));
    loop {
        write.write_all(&chunk).await?;
        if let Some(pace) = &mut pace {
            let due = pace.after_chunk(Instant::now());
            tokio::time::sleep_until(due).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use super::*;

    #[test]
    fn a_paced_flow_keeps_its_rate_and_bounds_what_it_catches_up() {
        let start = Instant::now();
        let mut pace = Pace::new(524.288, start);
        let per_chunk = Duration::from_millis(1);
        assert_eq!(pace.per_chunk, per_chunk);
        assert_eq!(pace.after_chunk(start), start + per_chunk);
        assert_eq!(pace.after_chunk(start), start + 2 * per_chunk);

        let late = start + Duration::from_millis(7);
        assert_eq!(pace.after_chunk(late), start + 3 * per_chunk);

        let stalled = start + Duration::from_secs(1);
        assert_eq!(pace.after_chunk(stalled), stalled - CATCH_UP + per_chunk);
    }

    /// Accepts `left` whole writes, recording each one's length, then fails.
    struct Recorder {
        left: usize,
        writes: Vec<usize>,
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.left == 0 {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            self.left -= 1;
            self.writes.push(buf.len());
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_unpaced_flow_writes_whole_chunks_and_never_waits() {
        let mut write = Recorder {
            left: 64,
            writes: Vec::new(),
        };
        let start = Instant::now();
        assert!(send_chunks(&mut write, 0xa5, None).await.is_err());
        assert_eq!(write.writes, vec![CHUNK; 64]);
        assert_eq!(Instant::now(), start);
    }

    #[tokio::test(start_paused = true)]
    async fn a_capped_flow_sends_at_its_rate() {
        let chunks = 2000;
        let mut write = Recorder {
            left: chunks,
            writes: Vec::new(),
        };
        let start = Instant::now();
        assert!(send_chunks(&mut write, 0xa5, Some(1000.0)).await.is_err());
        assert_eq!(write.writes, vec![CHUNK; chunks]);
        let mbit = (chunks * CHUNK) as f64 * 8.0 / 1e6 / start.elapsed().as_secs_f64();
        assert!((mbit / 1000.0 - 1.0).abs() < 0.001, "{mbit} Mbit/s");
    }
}
