use std::cell::RefCell;
use std::io;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::sync::lock;

pub const COPY_BUFFER_SIZE: usize = 32 * 1024;
const FIRST_CLASS: usize = 6;
const CLASSES: usize = 11;
/// What one relay write can release at once: `net::relay`'s batch of 8 buffers.
const LOCAL_LIMIT: usize = 8;

thread_local! {
    static BUFFERS: RefCell<Vec<Box<[u8]>>> = const { RefCell::new(Vec::new()) };
}

// Tasks can return a buffer on another worker; use PacketBuf's bounded overflow policy.
static SHARED: Mutex<Vec<Box<[u8]>>> = Mutex::new(Vec::new());

fn cached(size: usize) -> Option<Box<[u8]>> {
    let take = |buffers: &mut Vec<Box<[u8]>>| {
        buffers
            .iter()
            .rposition(|buffer| buffer.len() == size)
            .map(|index| buffers.swap_remove(index))
    };
    BUFFERS
        .try_with(|buffers| take(&mut buffers.borrow_mut()))
        .ok()
        .flatten()
        .or_else(|| take(&mut lock(&SHARED)))
}

fn recycle(storage: Box<[u8]>) {
    let overflow = BUFFERS
        .try_with(|buffers| {
            let mut buffers = buffers.borrow_mut();
            if buffers.len() < LOCAL_LIMIT {
                buffers.push(storage);
                None
            } else {
                Some(storage)
            }
        })
        .unwrap_or(None);
    if let Some(storage) = overflow {
        let mut buffers = lock(&SHARED);
        if buffers.len() < LOCAL_LIMIT * crate::packet::workers() {
            buffers.push(storage);
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BufferRequirements {
    pub mtu: usize,
    pub front: usize,
    pub rear: usize,
}

impl BufferRequirements {
    pub fn compose_writer(self, upstream: Self) -> Self {
        let mtu = match (self.mtu, upstream.mtu) {
            (0, mtu) | (mtu, 0) => mtu,
            (a, b) => a.min(b),
        };
        Self {
            mtu,
            front: self.front.saturating_add(upstream.front),
            rear: self.rear.saturating_add(upstream.rear),
        }
    }
}

pub fn poll_write_buffer<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    cx: &mut Context<'_>,
    buffer: &mut StreamBuffer,
) -> Poll<io::Result<usize>> {
    let written = ready!(Pin::new(writer).poll_write(cx, buffer.as_slice()))?;
    buffer.consume(written)?;
    Poll::Ready(Ok(written))
}

/// A sealed buffer that a writer has already reported as written and must finish sending
/// before it takes anything else.
#[derive(Default)]
pub struct OwnedDrain(Option<Owed>);

struct Owed {
    buffer: StreamBuffer,
    remaining: usize,
}

impl OwnedDrain {
    /// Takes the buffer's storage without copying; every byte of it is owed.
    pub fn start(&mut self, buffer: &mut StreamBuffer) {
        self.0 = Some(Owed {
            remaining: buffer.len(),
            buffer: buffer.take_owned(),
        });
    }

    pub fn is_pending(&self) -> bool {
        self.0.is_some()
    }

    /// The bytes still owed, in the storage taken by [`start`](Self::start).
    pub fn owed(&self) -> &[u8] {
        self.0.as_ref().map_or(&[], |owed| owed.buffer.as_slice())
    }

    /// Sends what is owed through `write`, which must consume what it reports written.
    /// A zero write is `WriteZero`; writing more than is owed, or leaving bytes unconsumed,
    /// is `InvalidData`.
    pub fn poll_drain(
        &mut self,
        mut write: impl FnMut(&mut StreamBuffer) -> Poll<io::Result<usize>>,
    ) -> Poll<io::Result<()>> {
        let Some(owed) = self.0.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        while owed.remaining > 0 {
            let written = ready!(write(&mut owed.buffer))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            owed.remaining = owed
                .remaining
                .checked_sub(written)
                .ok_or(io::ErrorKind::InvalidData)?;
        }
        if !owed.buffer.is_empty() {
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }
        self.0 = None;
        Poll::Ready(Ok(()))
    }
}

pub fn poll_read_buffer<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    cx: &mut Context<'_>,
    options: ReadBufferOptions,
) -> Poll<io::Result<StreamBuffer>> {
    let mut buffer = options.take();
    let filled = {
        let mut read = ReadBuf::new(buffer.spare_mut());
        ready!(Pin::new(reader).poll_read(cx, &mut read))?;
        read.filled().len()
    };
    if filled == 0 {
        return Poll::Ready(Ok(StreamBuffer::default()));
    }
    buffer.advance(filled)?;
    Poll::Ready(Ok(buffer))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadBufferOptions {
    capacity: usize,
    front: usize,
    rear: usize,
}

impl ReadBufferOptions {
    pub fn for_copy(reader: BufferRequirements, writer: BufferRequirements) -> io::Result<Self> {
        let mtu = reader.mtu.max(writer.mtu);
        let capacity = if mtu > 0 && mtu <= COPY_BUFFER_SIZE {
            mtu.checked_add(reader.front)
                .and_then(|n| n.checked_add(writer.front))
                .and_then(|n| n.checked_add(writer.rear))
                .ok_or(io::ErrorKind::InvalidInput)?
        } else {
            COPY_BUFFER_SIZE
        };
        if writer
            .front
            .checked_add(writer.rear)
            .is_none_or(|n| n >= capacity)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            capacity,
            front: writer.front,
            rear: writer.rear,
        })
    }

    /// Allocates a complete frame after its payload length is known, retaining the writer's
    /// headroom. Read temporary bytes into spare space, then advance only the completed payload.
    pub fn take_for_read(
        self,
        payload_len: usize,
        reader_overhead: usize,
    ) -> io::Result<StreamBuffer> {
        let capacity = self
            .front
            .checked_add(payload_len)
            .and_then(|n| n.checked_add(reader_overhead))
            .and_then(|n| n.checked_add(self.rear))
            .filter(|n| *n <= isize::MAX as usize)
            .ok_or(io::ErrorKind::InvalidInput)?;
        Ok(Self { capacity, ..self }.take())
    }

    /// Whether a buffer read before these options were known leaves the writer its room.
    pub fn fits(&self, buffer: &StreamBuffer) -> bool {
        buffer.headroom() >= self.front && buffer.tailroom() >= self.rear
    }

    pub fn take(self) -> StreamBuffer {
        let rounded = self
            .capacity
            .max(1 << FIRST_CLASS)
            .checked_next_power_of_two();
        let class = rounded.and_then(|n| {
            let class = n.trailing_zeros() as usize - FIRST_CLASS;
            (class < CLASSES).then_some(class)
        });
        let storage = class
            .and_then(|class| cached(1 << (class + FIRST_CLASS)))
            .unwrap_or_else(|| {
                vec![0; class.map_or(self.capacity, |n| 1 << (n + FIRST_CLASS))].into_boxed_slice()
            });
        StreamBuffer {
            storage: Some(storage),
            class,
            start: self.front,
            end: self.front,
            read_limit: self.capacity - self.rear,
            capacity: self.capacity,
        }
    }
}

#[derive(Default)]
pub struct StreamBuffer {
    storage: Option<Box<[u8]>>,
    class: Option<usize>,
    start: usize,
    end: usize,
    read_limit: usize,
    capacity: usize,
}

impl StreamBuffer {
    /// Moves the storage and view without allocating; leaves an empty value with no storage.
    pub fn take_owned(&mut self) -> Self {
        std::mem::take(self)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.storage
            .as_deref()
            .and_then(|s| s.get(self.start..self.end))
            .unwrap_or_default()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.storage
            .as_deref_mut()
            .and_then(|s| s.get_mut(self.start..self.end))
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn headroom(&self) -> usize {
        self.start
    }

    pub fn tailroom(&self) -> usize {
        self.capacity - self.end
    }

    pub fn spare_mut(&mut self) -> &mut [u8] {
        self.storage
            .as_deref_mut()
            .and_then(|s| s.get_mut(self.end..self.read_limit))
            .unwrap_or_default()
    }

    pub fn advance(&mut self, count: usize) -> io::Result<()> {
        let end = self
            .end
            .checked_add(count)
            .filter(|end| *end <= self.read_limit)
            .ok_or(io::ErrorKind::InvalidInput)?;
        self.end = end;
        Ok(())
    }

    pub fn consume(&mut self, count: usize) -> io::Result<()> {
        if count > self.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.start += count;
        Ok(())
    }

    pub fn prepend(&mut self, count: usize) -> io::Result<&mut [u8]> {
        let start = self
            .start
            .checked_sub(count)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let end = self.start;
        self.start = start;
        self.storage
            .as_deref_mut()
            .and_then(|s| s.get_mut(start..end))
            .ok_or_else(|| io::ErrorKind::InvalidInput.into())
    }

    pub fn append(&mut self, count: usize) -> io::Result<&mut [u8]> {
        let start = self.end;
        let end = start
            .checked_add(count)
            .filter(|end| *end <= self.capacity)
            .ok_or(io::ErrorKind::InvalidInput)?;
        self.end = end;
        self.storage
            .as_deref_mut()
            .and_then(|s| s.get_mut(start..end))
            .ok_or_else(|| io::ErrorKind::InvalidInput.into())
    }
}

impl Drop for StreamBuffer {
    fn drop(&mut self) {
        if let (Some(_), Some(storage)) = (self.class, self.storage.take()) {
            recycle(storage);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_frame_preserves_writer_space_and_hides_temporary_reader_bytes() {
        let options = ReadBufferOptions::for_copy(
            BufferRequirements::default(),
            BufferRequirements {
                mtu: 200,
                front: 18,
                rear: 16,
            },
        )
        .unwrap();
        let mut buffer = options.take_for_read(3, 16).unwrap();
        assert_eq!(buffer.headroom(), 18);
        assert_eq!(buffer.spare_mut().len(), 19);
        buffer.spare_mut()[..3].copy_from_slice(b"abc");
        buffer.spare_mut()[3..].fill(0xFA);
        buffer.advance(3).unwrap();
        assert_eq!(buffer.as_slice(), b"abc");
        assert_eq!(buffer.headroom(), 18);
        assert_eq!(buffer.tailroom(), 32);
    }

    #[test]
    fn a_complete_large_frame_can_exceed_the_generic_copy_buffer() {
        let options = ReadBufferOptions::for_copy(Default::default(), Default::default()).unwrap();
        let mut buffer = options.take_for_read(65535, 16).unwrap();
        assert_eq!(buffer.spare_mut().len(), 65551);
        assert!(buffer.class.is_none());
        buffer.advance(65535).unwrap();
        let pointer = buffer.as_slice().as_ptr();
        let owner = buffer.take_owned();
        assert_empty(&mut buffer);
        assert_eq!(owner.as_slice().as_ptr(), pointer);
        assert_eq!(owner.len(), 65535);
        assert_eq!(owner.tailroom(), 16);
    }

    #[test]
    fn invalid_known_frame_lengths_are_rejected_before_allocation() {
        let options = ReadBufferOptions::for_copy(
            Default::default(),
            BufferRequirements {
                front: 18,
                rear: 16,
                ..Default::default()
            },
        )
        .unwrap();
        for (payload, extra) in [(usize::MAX, 16), (0, usize::MAX), (isize::MAX as usize, 0)] {
            assert_eq!(
                options
                    .take_for_read(payload, extra)
                    .err()
                    .map(|e| e.kind()),
                Some(io::ErrorKind::InvalidInput)
            );
        }
    }

    fn filled(bytes: &[u8]) -> StreamBuffer {
        let options = ReadBufferOptions::for_copy(Default::default(), Default::default()).unwrap();
        let mut buffer = options.take_for_read(bytes.len(), 0).unwrap();
        buffer.spare_mut()[..bytes.len()].copy_from_slice(bytes);
        buffer.advance(bytes.len()).unwrap();
        buffer
    }

    fn drain_error(
        drain: &mut OwnedDrain,
        write: impl FnMut(&mut StreamBuffer) -> Poll<io::Result<usize>>,
    ) -> Option<io::ErrorKind> {
        match drain.poll_drain(write) {
            Poll::Ready(Err(error)) => Some(error.kind()),
            _ => None,
        }
    }

    #[test]
    fn an_owned_drain_resumes_after_pending_and_partial_writes() {
        let mut source = filled(b"abcdef");
        let pointer = source.as_slice().as_ptr();
        let mut drain = OwnedDrain::default();
        drain.start(&mut source);
        assert_empty(&mut source);
        let mut sent = Vec::new();
        let mut turns = [Some(2), None, Some(3), Some(1)].into_iter();
        let mut write = |buffer: &mut StreamBuffer| match turns.next().flatten() {
            Some(count) => {
                if sent.is_empty() {
                    assert_eq!(buffer.as_slice().as_ptr(), pointer);
                }
                sent.extend_from_slice(&buffer.as_slice()[..count]);
                buffer.consume(count)?;
                Poll::Ready(Ok(count))
            }
            None => Poll::Pending,
        };
        assert!(drain.poll_drain(&mut write).is_pending());
        assert!(matches!(drain.poll_drain(&mut write), Poll::Ready(Ok(()))));
        assert_eq!(sent, b"abcdef");
        assert!(matches!(
            drain.poll_drain(|_| unreachable!()),
            Poll::Ready(Ok(()))
        ));
    }

    #[test]
    fn an_owned_drain_rejects_a_zero_write_an_overrun_and_an_unconsumed_tail() {
        let mut drain = OwnedDrain::default();
        drain.start(&mut filled(b"abc"));
        assert_eq!(
            drain_error(&mut drain, |_| Poll::Ready(Ok(0))),
            Some(io::ErrorKind::WriteZero)
        );

        let mut drain = OwnedDrain::default();
        drain.start(&mut filled(b"abc"));
        assert_eq!(
            drain_error(&mut drain, |_| Poll::Ready(Ok(4))),
            Some(io::ErrorKind::InvalidData)
        );

        let mut drain = OwnedDrain::default();
        drain.start(&mut filled(b"abc"));
        assert_eq!(
            drain_error(&mut drain, |_| Poll::Ready(Ok(3))),
            Some(io::ErrorKind::InvalidData)
        );
    }

    fn assert_empty(buffer: &mut StreamBuffer) {
        assert!(buffer.storage.is_none());
        assert!(buffer.class.is_none());
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.headroom(), 0);
        assert_eq!(buffer.tailroom(), 0);
        assert!(buffer.as_slice().is_empty());
        assert!(buffer.as_mut_slice().is_empty());
        assert!(buffer.spare_mut().is_empty());
        assert!(buffer.advance(1).is_err());
        assert!(buffer.consume(1).is_err());
        assert!(buffer.prepend(1).is_err());
        assert!(buffer.append(1).is_err());
        assert_eq!(buffer.start, 0);
        assert_eq!(buffer.end, 0);
        assert_eq!(buffer.read_limit, 0);
        assert_eq!(buffer.capacity, 0);
    }

    #[test]
    fn an_owned_handoff_preserves_the_storage_and_complete_view() {
        let mut source = ReadBufferOptions::for_copy(
            BufferRequirements::default(),
            BufferRequirements {
                mtu: 100,
                front: 18,
                rear: 16,
            },
        )
        .unwrap()
        .take();
        source.spare_mut()[..7].copy_from_slice(b"payload");
        source.advance(7).unwrap();
        source.consume(2).unwrap();
        let pointer = source.as_slice().as_ptr();
        let bounds = (
            source.headroom(),
            source.tailroom(),
            source.spare_mut().len(),
        );
        let class = source.class;

        let mut owned = source.take_owned();
        assert_empty(&mut source);
        assert_eq!(owned.as_slice().as_ptr(), pointer);
        assert_eq!(owned.as_slice(), b"yload");
        assert_eq!(owned.class, class);
        assert_eq!(
            (owned.headroom(), owned.tailroom(), owned.spare_mut().len()),
            bounds
        );
        owned.prepend(2).unwrap().copy_from_slice(b"he");
        owned.append(3).unwrap().copy_from_slice(b"tag");
        assert_eq!(owned.as_slice(), b"heyloadtag");
    }

    #[test]
    fn an_empty_buffer_and_its_handoff_expose_no_memory() {
        let mut empty = StreamBuffer::default();
        assert_empty(&mut empty);
        let mut handed = empty.take_owned();
        assert_empty(&mut empty);
        assert_empty(&mut handed);
    }

    #[test]
    fn a_buffer_past_a_full_local_cache_reaches_a_shared_pool_a_holder_poisoned() {
        const SIZE: usize = 12_345;
        concord_test_support::poison(&SHARED);
        lock(&SHARED).clear();
        std::thread::spawn(|| {
            for _ in 0..=LOCAL_LIMIT {
                recycle(vec![0; SIZE].into_boxed_slice());
            }
        })
        .join()
        .unwrap();
        let taken = std::thread::spawn(|| cached(SIZE).map(|buffer| buffer.len()));
        assert_eq!(taken.join().unwrap(), Some(SIZE));
    }

    #[test]
    fn an_owned_handoff_recycles_once_in_either_drop_order() {
        let options = ReadBufferOptions::for_copy(Default::default(), Default::default()).unwrap();
        for source_first in [true, false] {
            BUFFERS.with(|buffers| buffers.borrow_mut().clear());
            let mut source = options.take();
            let pointer = source.spare_mut().as_ptr();
            let owned = source.take_owned();
            let occurrences = || {
                BUFFERS.with(|buffers| {
                    buffers
                        .borrow()
                        .iter()
                        .filter(|buffer| buffer.as_ptr() == pointer)
                        .count()
                })
            };
            assert_eq!(occurrences(), 0);
            if source_first {
                drop(source);
                assert_eq!(occurrences(), 0);
                drop(owned);
            } else {
                drop(owned);
                assert_eq!(occurrences(), 1);
                drop(source);
            }
            assert_eq!(occurrences(), 1);
            let mut reused = options.take();
            assert_eq!(reused.spare_mut().as_ptr(), pointer);
            let mut another = options.take();
            assert_ne!(another.spare_mut().as_ptr(), pointer);
        }
    }

    #[test]
    fn a_writer_chain_combines_headroom_and_uses_the_smallest_nonzero_mtu() {
        let own = BufferRequirements {
            mtu: 16383,
            front: 18,
            rear: 16,
        };
        assert_eq!(own.compose_writer(Default::default()), own);
        assert_eq!(BufferRequirements::default().compose_writer(own), own);
        assert_eq!(
            own.compose_writer(BufferRequirements {
                mtu: 1400,
                front: 4,
                rear: 8
            }),
            BufferRequirements {
                mtu: 1400,
                front: 22,
                rear: 24
            }
        );
    }

    #[test]
    fn copy_size_follows_the_reader_and_writer_requirements() {
        let cases = [
            (0, 0, COPY_BUFFER_SIZE),
            (0, 0x3fff, 0x3fff),
            (0x2000, 0x3fff, 0x3fff),
            (0x4000, 0x3fff, 0x4000),
            (0, 0xffff, COPY_BUFFER_SIZE),
            (0x10000, 0x3fff, COPY_BUFFER_SIZE),
        ];
        for (read_mtu, write_mtu, expected) in cases {
            let mut buffer = ReadBufferOptions::for_copy(
                BufferRequirements {
                    mtu: read_mtu,
                    ..Default::default()
                },
                BufferRequirements {
                    mtu: write_mtu,
                    ..Default::default()
                },
            )
            .unwrap()
            .take();
            assert_eq!(buffer.spare_mut().len(), expected);
        }
    }

    #[test]
    fn headroom_and_tags_do_not_move_or_expose_the_payload() {
        let options = ReadBufferOptions::for_copy(
            BufferRequirements {
                mtu: 100,
                front: 2,
                rear: 0,
            },
            BufferRequirements {
                mtu: 80,
                front: 18,
                rear: 16,
            },
        )
        .unwrap();
        let mut buffer = options.take();
        assert_eq!(buffer.spare_mut().len(), 102);
        let pointer = buffer.spare_mut().as_ptr();
        buffer.spare_mut()[..7].copy_from_slice(b"payload");
        buffer.advance(7).unwrap();
        assert_eq!(buffer.as_slice().as_ptr(), pointer);
        buffer.prepend(18).unwrap().fill(1);
        buffer.append(16).unwrap().fill(2);
        assert_eq!(&buffer.as_slice()[18..25], b"payload");
        assert_eq!(buffer.as_slice()[18..].as_ptr(), pointer);
        assert!(buffer.prepend(1).is_err());
        let len = buffer.len();
        assert!(buffer.consume(len + 1).is_err());
        assert_eq!(buffer.len(), len);
    }

    #[test]
    fn default_capacity_includes_reserved_headroom() {
        let mut buffer = ReadBufferOptions::for_copy(
            BufferRequirements::default(),
            BufferRequirements {
                front: 18,
                rear: 16,
                ..Default::default()
            },
        )
        .unwrap()
        .take();
        assert_eq!(buffer.spare_mut().len(), COPY_BUFFER_SIZE - 34);
        assert!(
            ReadBufferOptions::for_copy(
                BufferRequirements::default(),
                BufferRequirements {
                    front: COPY_BUFFER_SIZE,
                    ..Default::default()
                },
            )
            .is_err()
        );
    }

    #[test]
    fn released_storage_is_reused_without_sharing_a_live_buffer() {
        let options = ReadBufferOptions::for_copy(Default::default(), Default::default()).unwrap();
        let mut first = options.take();
        let first_pointer = first.spare_mut().as_ptr();
        let mut second = options.take();
        assert_ne!(first_pointer, second.spare_mut().as_ptr());
        drop(first);
        let mut third = options.take();
        assert_eq!(first_pointer, third.spare_mut().as_ptr());
        assert_eq!(third.len(), 0);
    }
}
